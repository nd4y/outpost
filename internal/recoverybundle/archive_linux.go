package recoverybundle

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
)

const manifestName = "manifest.json"

const instructionsEN = `This package contains plaintext recovery secrets. Keep it only in owner-controlled private storage, separately from sources and replicas. Do not upload it to a shared node or send it to an external model.

Retain the complete package SHA-256 separately. Verify that digest before using or extracting the package. A self-described hash is not an independent trust anchor. The package contains no backup payloads, storage credentials, control-plane account or source signing key.

Use a compatible Outpost executable to inspect/extract with the separately retained package digest. Alternatively, after checking the whole package with a trusted SHA-256 tool, unpack it in a new private directory. Select the tools archive for Linux amd64 or arm64 and unpack it into a separate new private tools directory. The archives include executable tools and licenses; the package itself never executes them.

Use the extracted recovery-owner.json and trust.json with outpost restore-replica, an independently available complete ciphertext replica, an explicit generation ID and a new output directory. For an independently exported encrypted file kit, use outpost restore-kit with the same recovery owner and the exact selected version ID. No source, original journal or control account is needed.

checkpoint.json, when present, preserves the last saved signed source checkpoint and its original verification time. It is historical evidence, not proof that storage is healthy now or that no later version exists. An absent or old checkpoint limits freshness knowledge; it does not prevent decrypting an explicitly chosen valid available version with matching recovery material. Keep old packages when rotating keys, and prove old/new recovery before retiring any material. Exporting a package does not rotate or revoke a key.
`

const instructionsRU = `Этот комплект содержит открытые секреты восстановления. Храните его только в приватном хранилище владельца, отдельно от источников и реплик. Не загружайте его на общую ноду и не передавайте внешней модели.

Сохраните SHA-256 всего комплекта отдельно. Перед использованием или распаковкой проверьте именно этот хеш. Хеш из самого файла не является независимым основанием доверия. Комплект не содержит резервных данных, доступов к хранилищу, учётной записи control plane или закрытого ключа подписи источника.

Совместимый Outpost проверяет и распаковывает комплект по отдельно сохранённому хешу. Другой вариант - проверить весь файл доверенной утилитой SHA-256 и распаковать его в новый приватный каталог. Выберите архив инструментов для Linux amd64 или arm64 и распакуйте его в отдельный новый приватный каталог. Архивы содержат исполняемые инструменты и лицензии; сам комплект ничего не запускает.

Для outpost restore-replica используйте recovery-owner.json, trust.json, независимо доступную полную зашифрованную реплику, явно выбранный ID поколения и новый каталог результата. Для независимо выгруженного зашифрованного комплекта файла используйте outpost restore-kit с тем же владельцем восстановления и точным ID версии. Источник, первоначальный журнал и учётная запись control plane не нужны.

checkpoint.json, если он есть, сохраняет последнюю выгруженную подписанную контрольную точку источника и исходное время проверки. Это историческое доказательство, а не подтверждение текущей исправности хранилища или отсутствия более новой версии. Отсутствующая или старая точка ограничивает знание актуальности, но не мешает расшифровать явно выбранную корректную доступную версию с подходящими ключами. При ротации сохраняйте старые комплекты и проверяйте восстановление старых и новых данных до вывода ключей из использования. Выгрузка комплекта сама по себе не меняет и не отзывает ключ.
`

func (m Metadata) validate() error {
	if m.Format != Format || m.CreatedUnix < 1 || m.CreatedUnix > 1<<40 || !storage.ID(m.Domain) || !storage.ID(m.Repository) || m.Epoch == 0 || !revisionPattern.MatchString(m.ToolRevision) || !storage.ID(m.ToolManifestSHA256) || len(m.Architectures) < 1 || len(m.Architectures) > 2 || len(m.FileKitFormats) != 2 || m.FileKitFormats[0] != filekit.Format || m.FileKitFormats[1] != filekit.TypedFormat {
		return ErrInvalid
	}
	allowed := map[string]int64{"recovery-owner.json": 4096, "trust.json": 4096, "instructions.en.txt": 16384, "instructions.ru.txt": 16384, "tools/manifest.json": MaxManifestBytes}
	if m.CheckpointPresent {
		allowed["checkpoint.json"] = 65536
	}
	previous := ""
	for _, arch := range m.Architectures {
		if (arch != "amd64" && arch != "arm64") || arch <= previous {
			return ErrInvalid
		}
		previous = arch
		allowed["tools/outpost-linux-"+arch+".tar.gz"] = MaxToolBytes
	}
	if len(m.Files) != len(allowed) {
		return ErrInvalid
	}
	var total int64
	for name, item := range m.Files {
		limit, ok := allowed[name]
		if !ok || item.Bytes < 1 || item.Bytes > limit || !storage.ID(item.SHA256) {
			return ErrInvalid
		}
		total += (item.Bytes+511)/512*512 + 512
	}
	if total+(65536+511)/512*512+1536 > MaxPackageBytes {
		return ErrCapacity
	}
	return nil
}

func packageMembers(m Material, t *tools, now int64) (Metadata, map[string][]byte, error) {
	var meta Metadata
	if e := m.validate(); e != nil {
		return meta, nil, e
	}
	owner, e := json.Marshal(m.Owner)
	if e != nil {
		return meta, nil, e
	}
	trust, e := json.Marshal(m.Trust)
	if e != nil {
		return meta, nil, e
	}
	members := map[string][]byte{"recovery-owner.json": owner, "trust.json": trust, "instructions.en.txt": []byte(instructionsEN), "instructions.ru.txt": []byte(instructionsRU), "tools/manifest.json": t.raw}
	if len(m.Checkpoint) > 0 {
		members["checkpoint.json"] = bytes.Clone(m.Checkpoint)
	}
	arches := append([]string(nil), t.manifest.Architectures...)
	sort.Strings(arches)
	meta = Metadata{Format: Format, CreatedUnix: now, Domain: m.Trust.Domain, Repository: m.Trust.Repository, Epoch: m.Trust.Epoch, FileKitFormats: []string{filekit.Format, filekit.TypedFormat}, ToolRevision: t.manifest.Revision, ToolManifestSHA256: t.digest, Architectures: arches, CheckpointPresent: len(m.Checkpoint) > 0, Files: map[string]File{}}
	for name, raw := range members {
		meta.Files[name] = File{SHA256: storage.Hash(raw), Bytes: int64(len(raw))}
	}
	for _, arch := range arches {
		name := "outpost-linux-" + arch + ".tar.gz"
		meta.Files["tools/"+name] = t.manifest.Files[name]
	}
	return meta, members, meta.validate()
}

type countingWriter struct {
	w        io.Writer
	n, limit int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.limit-w.n {
		return 0, ErrCapacity
	}
	n, e := w.w.Write(p)
	w.n += int64(n)
	return n, e
}

func writePackage(ctx context.Context, destination io.Writer, m Material, t *tools) (Receipt, error) {
	meta, members, e := packageMembers(m, t, time.Now().Unix())
	if e != nil {
		return Receipt{}, e
	}
	raw, e := json.Marshal(meta)
	if e != nil {
		return Receipt{}, e
	}
	digest := sha256.New()
	bounded := &countingWriter{w: io.MultiWriter(destination, digest), limit: MaxPackageBytes}
	archive := tar.NewWriter(bounded)
	entry := func(name string, size int64, read io.Reader) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		h := &tar.Header{Name: name, Mode: 0600, Size: size, Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if e := archive.WriteHeader(h); e != nil {
			return e
		}
		hash := sha256.New()
		n, e := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(contextReader{ctx, read}, size+1))
		if e != nil {
			return e
		}
		if n != size {
			return ErrInvalid
		}
		if name != manifestName && hex.EncodeToString(hash.Sum(nil)) != meta.Files[name].SHA256 {
			return ErrInvalid
		}
		return nil
	}
	if e = entry(manifestName, int64(len(raw)), bytes.NewReader(raw)); e != nil {
		return Receipt{}, e
	}
	for _, name := range names(meta.Files) {
		if data, ok := members[name]; ok {
			e = entry(name, int64(len(data)), bytes.NewReader(data))
		} else {
			f, openErr := regular(t.root, name[len("tools/"):], MaxToolBytes, false)
			if openErr != nil {
				return Receipt{}, openErr
			}
			e = entry(name, meta.Files[name].Bytes, f)
			e = errors.Join(e, f.Close())
		}
		if e != nil {
			return Receipt{}, e
		}
	}
	if e = archive.Close(); e != nil {
		return Receipt{}, e
	}
	out, e := receipt(meta, m)
	if e != nil {
		return Receipt{}, e
	}
	out.SHA256 = hex.EncodeToString(digest.Sum(nil))
	out.Bytes = bounded.n
	return out, nil
}

type entrySink func(name string) (io.WriteCloser, error)

// readPackage validates a fixed, bounded entry set without ever interpreting an
// archive member name as an arbitrary filesystem path. A sink is only invoked
// for the exact validated names and is never allowed to execute tool content.
func readPackage(ctx context.Context, input io.Reader, sink entrySink) (out Receipt, err error) {
	defer func() {
		if e := ctx.Err(); e != nil {
			out = Receipt{}
			err = e
		}
	}()
	digest := sha256.New()
	limited := &io.LimitedReader{R: contextReader{ctx, input}, N: MaxPackageBytes + 1}
	reader := io.TeeReader(limited, digest)
	archive := tar.NewReader(reader)
	readEntry := func(name string, expected File, small bool) ([]byte, error) {
		h, e := archive.Next()
		if e != nil {
			return nil, ErrInvalid
		}
		if h.Name != name || h.Size != expected.Bytes || h.Typeflag != tar.TypeReg || h.Mode != 0600 || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Linkname != "" || h.ModTime.Unix() != 0 || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 {
			return nil, ErrInvalid
		}
		var writer io.WriteCloser
		if sink != nil {
			writer, e = sink(name)
			if e != nil {
				return nil, e
			}
			defer func() {
				if writer != nil {
					writer.Close()
				}
			}()
		}
		hash := sha256.New()
		var target io.Writer = hash
		if writer != nil {
			target = io.MultiWriter(hash, writer)
		}
		var data bytes.Buffer
		if small {
			target = io.MultiWriter(target, &data)
		}
		n, e := io.Copy(target, contextReader{ctx, archive})
		if e != nil {
			return nil, e
		}
		if n != expected.Bytes || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return nil, ErrInvalid
		}
		if writer != nil {
			e = writer.Close()
			writer = nil
			if e != nil {
				return nil, e
			}
		}
		return data.Bytes(), nil
	}
	h, e := archive.Next()
	if e != nil || h.Name != manifestName || h.Size < 1 || h.Size > 65536 || h.Typeflag != tar.TypeReg || h.Mode != 0600 || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Linkname != "" || h.ModTime.Unix() != 0 || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 {
		return out, ErrInvalid
	}
	raw, e := io.ReadAll(archive)
	if e != nil {
		return out, e
	}
	var meta Metadata
	if storage.Decode(raw, &meta, 65536) != nil || meta.validate() != nil {
		return out, ErrInvalid
	}
	expectedBytes := int64(512 + (len(raw)+511)/512*512 + 1024)
	for _, item := range meta.Files {
		expectedBytes += 512 + (item.Bytes+511)/512*512
	}
	if sink != nil {
		w, e := sink(manifestName)
		if e != nil {
			return out, e
		}
		_, e = w.Write(raw)
		e = errors.Join(e, w.Close())
		if e != nil {
			return out, e
		}
	}
	var material Material
	var tool toolManifest
	for _, name := range names(meta.Files) {
		if name == "tools/manifest.json" {
			data, e := readEntry(name, meta.Files[name], true)
			if e != nil {
				return out, e
			}
			tool, e = validateTools(data, meta.ToolManifestSHA256, meta.ToolRevision)
			if e != nil {
				return out, e
			}
			arches := append([]string(nil), tool.Architectures...)
			sort.Strings(arches)
			a, _ := json.Marshal(arches)
			b, _ := json.Marshal(meta.Architectures)
			if !bytes.Equal(a, b) {
				return out, ErrInvalid
			}
			continue
		}
		if name == "recovery-owner.json" || name == "trust.json" || name == "checkpoint.json" {
			data, e := readEntry(name, meta.Files[name], true)
			if e != nil {
				return out, e
			}
			switch name {
			case "recovery-owner.json":
				e = storage.Decode(data, &material.Owner, 4096)
			case "trust.json":
				e = storage.Decode(data, &material.Trust, 4096)
			case "checkpoint.json":
				material.Checkpoint = data
			}
			if e != nil {
				return out, ErrInvalid
			}
			continue
		}
		// Tool archives are checked against the independently selected manifest
		// again during inspection; a manifest alone is not a validated reader.
		if name == "tools/outpost-linux-amd64.tar.gz" || name == "tools/outpost-linux-arm64.tar.gz" {
			arch := "amd64"
			if name == "tools/outpost-linux-arm64.tar.gz" {
				arch = "arm64"
			}
			ref, ok := tool.Files[name[len("tools/"):]]
			if !ok || ref != meta.Files[name] {
				return out, ErrInvalid
			}
			h, e := archive.Next()
			if e != nil || h.Name != name || h.Size != ref.Bytes || h.Typeflag != tar.TypeReg || h.Mode != 0600 || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Linkname != "" || h.ModTime.Unix() != 0 || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 {
				return out, ErrInvalid
			}
			var stream io.Reader = archive
			var w io.WriteCloser
			if sink != nil {
				w, e = sink(name)
				if e != nil {
					return out, e
				}
				stream = io.TeeReader(stream, w)
			}
			e = verifyToolArchive(ctx, stream, arch, tool)
			if w != nil {
				e = errors.Join(e, w.Close())
			}
			if e != nil {
				return out, e
			}
			continue
		}
		if _, e = readEntry(name, meta.Files[name], false); e != nil {
			return out, e
		}
	}
	if _, e = archive.Next(); e != io.EOF {
		return out, ErrInvalid
	}
	var extra [1]byte
	if n, e := reader.Read(extra[:]); n != 0 || e != io.EOF {
		return out, ErrInvalid
	}
	if MaxPackageBytes+1-limited.N != expectedBytes {
		return out, ErrInvalid
	}
	if e = material.validate(); e != nil || material.Trust.Domain != meta.Domain || material.Trust.Repository != meta.Repository || material.Trust.Epoch != meta.Epoch || meta.CheckpointPresent != (len(material.Checkpoint) > 0) {
		return out, ErrInvalid
	}
	out, e = receipt(meta, material)
	if e != nil {
		return Receipt{}, e
	}
	out.SHA256 = hex.EncodeToString(digest.Sum(nil))
	out.Bytes = MaxPackageBytes + 1 - limited.N
	return out, nil
}

// Inspect authenticates the entire private artifact before parsing any of its
// secrets. It returns only opaque metadata, never recovery key material.
func Inspect(ctx context.Context, input *os.File, expected string) (Receipt, error) {
	if input == nil || !storage.ID(expected) {
		return Receipt{}, ErrInvalid
	}
	info, e := input.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > MaxPackageBytes {
		return Receipt{}, ErrDenied
	}
	if _, e = input.Seek(0, io.SeekStart); e != nil {
		return Receipt{}, e
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(contextReader{ctx, input}, MaxPackageBytes+1))
	if e != nil {
		return Receipt{}, e
	}
	if n != info.Size() || hex.EncodeToString(h.Sum(nil)) != expected {
		return Receipt{}, ErrInvalid
	}
	if _, e = input.Seek(0, io.SeekStart); e != nil {
		return Receipt{}, e
	}
	out, e := readPackage(ctx, input, nil)
	if e != nil {
		return Receipt{}, e
	}
	if out.SHA256 != expected || out.Bytes != n {
		return Receipt{}, ErrInvalid
	}
	return out, nil
}
