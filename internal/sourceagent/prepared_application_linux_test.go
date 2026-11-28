package sourceagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

// The native producer is an isolated test application, not an executable
// received from shared configuration. It keeps an uncommitted WAL transaction
// open while another connection uses SQLite's actual online backup API.
const preparedSQLiteProducer = `import json,os,pathlib,sqlite3,sys,time
source,out,marker=sys.argv[1],pathlib.Path(sys.argv[2]),int(sys.argv[3])
out.mkdir(mode=0o700)
live=sqlite3.connect(source)
assert live.execute('pragma journal_mode=wal').fetchone()[0]=='wal'
with live:
 live.execute('create table if not exists accounts(id integer primary key,balance integer not null)')
 live.execute('create table if not exists metadata(marker integer not null)')
 live.execute('create table if not exists payload(id integer primary key,value blob not null)')
 live.execute('delete from accounts')
 live.executemany('insert into accounts values(?,?)',[(1,100+marker),(2,900-marker)])
 live.execute('delete from metadata')
 live.execute('insert into metadata values(?)',(marker,))
 live.executemany('insert or replace into payload values(?,?)',[(n,bytes([n%251])*1024) for n in range(512)])
live.execute('begin immediate')
live.execute('update accounts set balance=-999 where id=1')
live.execute('update metadata set marker=?',(marker+1000,))
reader=sqlite3.connect(source)
target=out/'application.sqlite'
snapshot=int(time.time())
copy=sqlite3.connect(target)
reader.backup(copy,pages=8,sleep=0.01)
assert copy.execute('pragma integrity_check').fetchone()[0]=='ok'
assert copy.execute('select marker from metadata').fetchone()[0]==marker
assert copy.execute('select sum(balance) from accounts').fetchone()[0]==1000
copy.execute('pragma journal_mode=delete')
copy.close();reader.close();live.rollback();live.close()
os.chmod(target,0o600)
fd=os.open(target,os.O_RDONLY);os.fsync(fd);os.close(fd)
fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
print(json.dumps({'snapshotUnix':snapshot,'completedUnix':int(time.time()),'libraryVersion':sqlite3.sqlite_version}))
`
const preparedSQLiteRestore = `import json,pathlib,sqlite3,sys
p=pathlib.Path(sys.argv[1]);c=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)
assert c.execute('pragma integrity_check').fetchone()[0]=='ok'
marker=c.execute('select marker from metadata').fetchone()[0]
assert marker==int(sys.argv[2])
assert c.execute('select balance from accounts order by id').fetchall()==[(100+marker,),(900-marker,)]
rows=c.execute('select id,value from payload order by id').fetchall()
assert len(rows)==512
assert all(value==bytes([n%251])*1024 for n,value in rows)
c.close();print(json.dumps({'marker':marker,'integrity':'ok','rows':len(rows)}))
`

func nativePreparedCommand(t *testing.T, script string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	argv := append([]string{"-c", script}, args...)
	raw, e := exec.CommandContext(ctx, "python3", argv...).CombinedOutput()
	if e != nil {
		t.Fatalf("isolated native application: %v %s", e, raw)
	}
	return raw
}

func TestPreparedSourceRestoresNativeSQLiteOnlineBackupsWithUncommittedWrites(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.Close())
	f.a = nil
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	f.b.Format = PreparedAgentFormat
	f.b.Profile.Consistency = "application"
	f.b.Local.Directory += "-native-prepared"
	f.b.Prepared = &PreparedSource{Trust: capture.PreparedTrust{Profile: f.b.Profile.ID, Origin: f.b.Profile.Origin, Method: "sqlite-online-backup-v1", Producer: pub, MaxBytes: f.b.Profile.MaxSourceBytes, MaxFiles: 16}, ManifestFile: filepath.Join(f.base, "native-current.json")}
	live := filepath.Join(f.base, "live.sqlite")
	type version struct {
		generation, checksum string
		snapshot             int64
	}
	var versions []version
	for index, rootName := range []string{"native-export-1", "native-export-2"} {
		marker := []string{"1", "2"}[index]
		raw := nativePreparedCommand(t, preparedSQLiteProducer, live, filepath.Join(f.tree, rootName), marker)
		var proof struct {
			SnapshotUnix   int64  `json:"snapshotUnix"`
			CompletedUnix  int64  `json:"completedUnix"`
			LibraryVersion string `json:"libraryVersion"`
		}
		must(t, json.Unmarshal(raw, &proof))
		if proof.LibraryVersion == "" {
			t.Fatal("native library not observed")
		}
		claim := capture.PreparedClaim{Sequence: uint64(index + 1), SnapshotUnix: proof.SnapshotUnix, CompletedUnix: proof.CompletedUnix, Root: rootName}
		manifest, e := CreatePreparedManifest(ctx, f.b, claim, key)
		must(t, e)
		must(t, os.WriteFile(f.b.Prepared.ManifestFile, manifest, 0600))
		m, e := capture.VerifyPreparedExport(manifest, f.b.Prepared.Trust, time.Now())
		must(t, e)
		if len(m.Files) != 1 || m.Files[0].Name != "application.sqlite" {
			t.Fatal("unexpected native export closure")
		}
		if index == 0 {
			f.a, e = Open(ctx, f.b, true)
			must(t, e)
		}
		must(t, f.a.Next(ctx))
		must(t, f.a.Run(ctx))
		status, e := f.a.Status(ctx)
		must(t, e)
		if status.Phase != "COMPLETE" || status.Prepared == nil || status.Prepared.SnapshotUnix != proof.SnapshotUnix || status.Prepared.Attestation != "producer-signed" {
			t.Fatal("native export completion not identified", status)
		}
		versions = append(versions, version{status.Generation, m.Files[0].SHA256, proof.SnapshotUnix})
		t.Log("native producer SQLite", proof.LibraryVersion, "committed version", index+1, "bytes", m.Files[0].Bytes)
	}
	// Move only synthetic producer files away from their enrolled paths. Neither
	// the application nor its exports can be consulted by independent recovery.
	must(t, os.Rename(live, filepath.Join(f.base, "unavailable-application.sqlite")))
	for _, rootName := range []string{"native-export-1", "native-export-2"} {
		must(t, os.Rename(filepath.Join(f.tree, rootName), filepath.Join(f.tree, "retained-"+rootName)))
	}
	for index, v := range versions {
		out := filepath.Join(f.base, []string{"native-restore-first", "native-restore-second"}[index])
		_, e = generation.RecoverMaterialized(ctx, f.replicaPath, v.generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		file := filepath.Join(out, "application.sqlite")
		raw, e := os.ReadFile(file)
		must(t, e)
		if storage.Hash(raw) != v.checksum {
			t.Fatal("restored native archive differs")
		}
		nativePreparedCommand(t, preparedSQLiteRestore, file, []string{"1", "2"}[index])
	}
	t.Log("two native SQLite online backups independently restored; integrity_check, committed balances, marker and 512 payload rows verified without original application or export paths")
}
