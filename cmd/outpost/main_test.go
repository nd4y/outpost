package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestSecretRejectsConfigInjectionAndAmbiguity(t *testing.T) {
 t.Setenv("OUTPOST_TEST_PASSWORD","safe\ninjected=yes")
 t.Setenv("OUTPOST_TEST_PASSWORD_FILE","")
 if _,err:=secret("OUTPOST_TEST_PASSWORD"); err==nil { t.Fatal("newline accepted") }
 file:=filepath.Join(t.TempDir(),"password")
 if err:=os.WriteFile(file,[]byte("file-secret\n"),0600);err!=nil { t.Fatal(err) }
 t.Setenv("OUTPOST_TEST_PASSWORD_FILE",file)
 if _,err:=secret("OUTPOST_TEST_PASSWORD");err==nil {t.Fatal("ambiguous credentials accepted")}
 t.Setenv("OUTPOST_TEST_PASSWORD","")
 got,err:=secret("OUTPOST_TEST_PASSWORD")
 if err!=nil || got!="file-secret" {t.Fatalf("secret file parsing: %q %v",got,err)}
}

func TestPeerCannotEnablePrivilegedFeaturesThroughInheritedEnvironment(t *testing.T) {
 t.Setenv("NB_MANAGEMENT_URL","https://management.example")
 t.Setenv("NB_SETUP_KEY","00000000-0000-0000-0000-000000000000")
 t.Setenv("NB_SETUP_KEY_FILE","")
 t.Setenv("NB_HOSTNAME","outpost-test")
 t.Setenv("NB_USE_NETSTACK_MODE","false")
 t.Setenv("NB_ENABLE_CAPTURE","true")
 t.Setenv("NB_NETSTACK_SKIP_PROXY","false")
 t.Setenv("NB_ALLOW_SERVER_SSH","true")
 t.Setenv("NB_ALLOW_REMOTE_JOBS","true")
 t.Setenv("LD_PRELOAD","/data/malicious.so")
 env,err:=netbirdEnv()
 if err!=nil {t.Fatal(err)}
 values:=map[string]string{}
 for _,item:=range env { parts:=strings.SplitN(item,"=",2);values[parts[0]]=parts[1] }
 for key,want:=range map[string]string{
  "NB_USE_NETSTACK_MODE":"true","NB_ENABLE_CAPTURE":"false","NB_NETSTACK_SKIP_PROXY":"true",
  "NB_DISABLE_CLIENT_ROUTES":"true","NB_DISABLE_SERVER_ROUTES":"true","NB_DISABLE_DNS":"true",
  "NB_ALLOW_SERVER_SSH":"false","NB_ALLOW_REMOTE_JOBS":"false",
 } {
  if values[key]!=want {t.Errorf("%s=%q, want %s",key,values[key],want)}
 }
 if _,ok:=values["LD_PRELOAD"];ok {t.Error("untrusted inherited environment reached child")}
 t.Setenv("NB_MANAGEMENT_URL","http://management.example")
 if _,err:=netbirdEnv();err==nil {t.Error("unencrypted enrollment URL accepted")}
 t.Setenv("NB_MANAGEMENT_URL","https://user:password@management.example")
 if _,err:=netbirdEnv();err==nil {t.Error("credentials in URL accepted")}
}
