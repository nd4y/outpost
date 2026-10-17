#!/bin/sh
# POSIX sh; terminal input stays separate from a curl/wget pipeline.
set +x
set -eu

main() {
    [ "$#" -eq 0 ] || { printf 'Usage: install.sh (no arguments)\n' >&2; exit 1; }
    umask 077
    for tool in docker stty od tr mkdir rmdir chown ls sleep; do
        command -v "$tool" >/dev/null 2>&1 || { printf 'Required command missing: %s\n' "$tool" >&2; exit 1; }
    done
    docker info >/dev/null 2>&1 || { printf 'Docker is unavailable. Start Docker or run the installer with Docker permissions.\n' >&2; exit 1; }
    # Bind paths must refer to this host, never a remote Docker daemon.
    endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null) || endpoint=
    if [ -z "${DOCKER_CONTEXT:-}" ]; then endpoint=${DOCKER_HOST:-$endpoint}; fi
    case "$endpoint" in unix://*) ;; *) printf 'A local Unix Docker socket is required.\n' >&2; exit 1 ;; esac
    if docker container inspect outpost >/dev/null 2>&1; then
        printf 'Container outpost already exists. No changes made. Use docker start outpost to restart it.\n' >&2
        exit 1
    fi
    exec 3<>/dev/tty || { printf 'An interactive terminal is required.\n' >&2; exit 1; }
    terminal_state=$(stty -g <&3)
    installed=0
    created_data=0
    need_data=0
    volume_created=0
    container_created=0
    helper_created=0
    pulled_image=0
    data=
    volume=
    helper=
    image=${OUTPOST_IMAGE:-ghcr.io/nd4y/outpost:edge}
    cleanup() {
        status=$?
        trap - 0 HUP INT TERM
        stty "$terminal_state" <&3 2>/dev/null || :
        unset setup_key
        cleanup_failed=0
        if [ "$helper_created" -eq 1 ] && docker container inspect "$helper" >/dev/null 2>&1; then
            docker rm -f "$helper" >/dev/null 2>&1 || cleanup_failed=1
        fi
        if [ "$installed" -ne 1 ]; then
            if [ "$container_created" -eq 1 ]; then docker rm -f outpost >/dev/null 2>&1 || cleanup_failed=1; fi
            if [ "$volume_created" -eq 1 ]; then docker volume rm "$volume" >/dev/null 2>&1 || cleanup_failed=1; fi
            if [ "$created_data" -eq 1 ] && [ "$cleanup_failed" -eq 0 ]; then rmdir "$data" 2>/dev/null || :; fi
            if [ "$pulled_image" -eq 1 ]; then docker image rm "$image" >/dev/null 2>&1 || :; fi
            if [ "" -ne 0 ]; then
                printf 'Rollback incomplete. Check container outpost, helper %s and volume %s.\n' "" "" >&2
            fi
            printf 'Installation did not complete. Rollback attempted; backup files are never deleted.\n' >&2
            printf 'If enrollment reached NetBird, remove the unused peer in its management console.\n' >&2
        fi
        exit "$status"
    }
    trap cleanup 0
    trap 'exit 130' INT
    trap 'exit 143' HUP TERM
    management=${NB_MANAGEMENT_URL:-https://api.netbird.io:443}
    case "$management" in https://?*) ;; *) printf 'NB_MANAGEMENT_URL must be HTTPS.\n' >&2; exit 1 ;; esac
    case "$management" in *'@'*|*'"'*|*' '*|*'
'*) printf 'Invalid NetBird management URL.\n' >&2; exit 1 ;; esac
    printf 'Outpost installer\nNetBird management: %s\n' "$management" >&3
    printf 'Dedicated backup directory (absolute path): ' >&3
    IFS= read -r data <&3 || exit 1
    case "$data" in /*) ;; *) printf 'An absolute directory path is required.\n' >&2; exit 1 ;; esac
    case "$data" in *','*|*':'*|*'
'*) printf 'This path cannot be represented safely as a Docker bind.\n' >&2; exit 1 ;; esac
    [ ! -L "$data" ] || { printf 'The selected directory must not be a symlink.\n' >&2; exit 1; }
    if [ -d "$data" ]; then
        data=$(CDPATH= cd -P "$data" && pwd -P)
    else
        parent=${data%/*}
        [ -n "$parent" ] || parent=/
        leaf=${data##*/}
        [ -n "$leaf" ] && [ "$leaf" != . ] && [ "$leaf" != .. ] && [ -d "$parent" ] || { printf 'The parent directory must already exist.\n' >&2; exit 1; }
        parent=$(CDPATH= cd -P "$parent" && pwd -P)
        data=${parent%/}/$leaf
        need_data=1
    fi
    case "$data" in /|/etc|/usr|/bin|/sbin|/dev|/proc|/sys|/run|/var|/var/lib|/var/lib/docker|/volume[0-9]|/volume[0-9][0-9]) printf 'Choose a dedicated backup subdirectory.\n' >&2; exit 1 ;; esac
    if [ "$need_data" -eq 0 ]; then
        [ -z "$(ls -A "$data")" ] || { printf 'A first installation requires an empty dedicated directory.\n' >&2; exit 1; }
    fi
    stty -echo <&3
    printf 'NetBird setup key (hidden): ' >&3
    IFS= read -r setup_key <&3 || exit 1
    stty "$terminal_state" <&3
    printf '\n' >&3
    [ "${#setup_key}" -ge 16 ] && [ "${#setup_key}" -le 512 ] || { printf 'A valid setup key is required.\n' >&2; exit 1; }
    token=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
    [ "${#token}" -eq 16 ] || { printf 'Cannot generate an installation identifier.\n' >&2; exit 1; }
    volume=outpost-state-$token
    helper=outpost-setup-$token
    hostname=outpost-$token
    docker image inspect "$image" >/dev/null 2>&1 || pulled_image=1
    printf 'Downloading container image...\n' >&3
    docker pull "$image" >/dev/null
    # Pin this installation to the exact image that was just pulled.
    image_id=$(docker image inspect "$image" --format '{{.Id}}')
    if [ "$need_data" -eq 1 ]; then
        mkdir -m 0700 "$data"
        created_data=1
        chown 65532:65532 "$data"
    fi
    docker volume create --label io.outpost.managed=installer-v1 "$volume" >/dev/null
    volume_created=1
    # Reserve the container name before passing the key to the temporary helper.
    docker create --name outpost --hostname "$hostname" --network bridge \
        --label io.outpost.managed=installer-v1 --label "io.outpost.state-volume=$volume" \
        --restart unless-stopped --user 65532:65532 --read-only --cap-drop ALL \
        --security-opt no-new-privileges:true --pids-limit 128 \
        --memory "${OUTPOST_MEMORY_LIMIT:-1g}" --memory-swap "${OUTPOST_MEMORY_LIMIT:-1g}" --cpu-shares 256 \
        --stop-timeout 20 --log-opt max-size=5m --log-opt max-file=2 \
        --mount "type=bind,src=$data,dst=/data" --mount "type=volume,src=$volume,dst=/state" \
        --tmpfs /run/outpost:rw,noexec,nosuid,nodev,size=4m,uid=65532,gid=65532,mode=0700 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700 \
        -e "NB_MANAGEMENT_URL=$management" -e "NB_HOSTNAME=$hostname" \
        -e OUTPOST_RSYNC_USER=backup "$image_id" >/dev/null
    container_created=1
    helper_created=1
    printf '%s\n' "$setup_key" | docker run --rm -i --name "$helper" --network none \
        --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --pids-limit 32 --memory 64m --memory-swap 64m --log-driver none \
        --mount "type=bind,src=$data,dst=/data" --mount "type=volume,src=$volume,dst=/state" \
        "$image_id" bootstrap
    unset setup_key
    helper_created=0
    docker start outpost >/dev/null
    printf 'Waiting for NetBird enrollment and receiver readiness...\n' >&3
    attempt=0
    while [ "$attempt" -lt 90 ]; do
        status=$(docker inspect outpost --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}')
        case "$status" in
            'running healthy') break ;;
            exited*|dead*|restarting*) printf 'Outpost failed to start; check the management URL, key, permissions and peer approval.\n' >&2; exit 1 ;;
        esac
        attempt=$((attempt + 1))
        sleep 2
    done
    [ "$attempt" -lt 90 ] || { printf 'Timed out waiting for Outpost.\n' >&2; exit 1; }
    # Never print the setup key. The generated rsync password is needed by Hyper Backup.
    password=$(docker exec outpost /usr/bin/outpost credentials)
    address=$(docker exec outpost /usr/bin/netbird status --ipv4) || address='see NetBird console'
    installed=1
    printf '\nOutpost is ready.\nNetBird IPv4: %s\nRsync: port 8873, user backup, module backup\nRsync password: %s\nMetrics: http://<NetBird-IP>:9090/metrics\nState volume: %s\n' "$address" "$password" "$volume" >&3
    unset password
    printf 'Save the rsync password and enable client-side encryption in Hyper Backup.\n' >&3
    printf 'No installer files or host services were installed. Backup data, the container image and the named state volume remain for operation.\n' >&3
}

main "$@"
