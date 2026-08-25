#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static int cmd_peers(void) {
    gm_sock_init();
    gm_ident id;
    gm_ident_load(&id);
    gm_peer peers[64];
    printf("scanning LAN...\n");
    int n = gm_disco_collect(&id, peers, 64, 2000);
    if (n == 0) {
        printf("\nno peers online\n");
        return 1;
    }
    printf("\n");
    for (int i = 0; i < n; i++) {
        char fingerprint[9];
        gm_hex(fingerprint, peers[i].sign_pk + 24, 4);
        char ip_port[64];
        uint16_t tcp_port = peers[i].port ? peers[i].port : gm_env_tcp_port();
        snprintf(ip_port, sizeof ip_port, "%s:%u", peers[i].ip, tcp_port);
        printf("  %c %-20s %-21s ~%s\n", '*', peers[i].name, ip_port, fingerprint);
    }
    return 0;
}

static int cmd_status(void) {
    gm_sock_init();
    gm_ident id;
    gm_ident_load(&id);
    char key_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    gm_hex(key_hex, id.sign_pk, crypto_sign_PUBLICKEYBYTES);
    char root[GM_PATH_MAX];
    if (!getcwd(root, sizeof root)) gm_die("cannot determine working directory");
    char display_name[GM_NAME_MAX];
    gm_ident_display(&id, display_name);
    printf("gitmesh %s\n", GM_VERSION);
    printf("user:     %s\n", id.user);
    printf("device:   %s\n", id.device);
    printf("display:  %s\n", display_name);
    printf("identity: %.16s...\n", key_hex);
    printf("project:  %s\n", root);

    gm_manifest old = {0};
    gm_manifest cur = {0};
    int have_index = gm_index_load(root, &old) == 0;
    gm_scan(root, &old, &cur);
    printf("indexed:  %s (%zu files)\n", have_index ? "yes" : "no", old.n);
    printf("current:  %zu files\n", cur.n);
    if (have_index) {
        size_t added = 0;
        size_t modified = 0;
        size_t deleted = 0;
        gm_diff(&old, &cur, &added, &modified, &deleted);
        printf("pending:  %zu changed / %zu added / %zu deleted\n",
               modified, added, deleted);
    } else {
        printf("pending:  first sync will transfer everything\n");
    }
    gm_manifest_free(&old);
    gm_manifest_free(&cur);
    return 0;
}

int main(int argc, char **argv) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    if (sodium_init() < 0)
        gm_die("libsodium init failed");

    if (argc < 2 || strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        printf("usage: gitmesh <command>\n"
               "\n"
               "  peers            list peers on the LAN\n"
               "  share            announce presence and accept transfers\n"
               "  status           show identity and project state\n"
               "  send <peer>      push project changes to peer\n"
               "  receive <peer>   pull peer's changes into this project\n"
               "  name [newname]   show or set user name\n"
               "  device [newname] show or set device name\n"
               "  export           print hex seed for backup\n"
               "  import <hex>     restore identity from hex seed\n");
        return argc < 2 ? 1 : 0;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "peers") == 0) return cmd_peers();
    if (strcmp(cmd, "status") == 0) return cmd_status();
    if (strcmp(cmd, "share") == 0) return gm_cmd_share();
    if (strcmp(cmd, "name") == 0) {
        if (argc == 2) {
            gm_ident id;
            gm_ident_load(&id);
            printf("%s\n", id.user);
            return 0;
        }
        if (argc == 3) {
            if (gm_ident_set_user(argv[2]) != 0) gm_die("invalid name");
            printf("user name set to %s\n", argv[2]);
            return 0;
        }
        gm_die("usage: gitmesh name [newname]");
    }
    if (strcmp(cmd, "device") == 0) {
        if (argc == 2) {
            gm_ident id;
            gm_ident_load(&id);
            printf("%s\n", id.device);
            return 0;
        }
        if (argc == 3) {
            if (gm_ident_set_device(argv[2]) != 0) gm_die("invalid name");
            printf("device name set to %s\n", argv[2]);
            return 0;
        }
        gm_die("usage: gitmesh device [newname]");
    }
    if (strcmp(cmd, "export") == 0) {
        char out[crypto_sign_SEEDBYTES * 2 + 1];
        if (gm_ident_export(out, sizeof out) != 0) gm_die("export failed");
        printf("%s\n", out);
        return 0;
    }
    if (strcmp(cmd, "import") == 0) {
        if (argc < 3) gm_die("usage: gitmesh import <hex>");
        if (gm_ident_import(argv[2]) != 0) gm_die("invalid hex");
        printf("identity imported\n");
        return 0;
    }
    if ((strcmp(cmd, "send") == 0 || strcmp(cmd, "receive") == 0)) {
        if (argc < 3)
            gm_die("usage: gitmesh %s <peer>", cmd);
        return strcmp(cmd, "send") == 0 ? gm_cmd_send(argv[2])
                                        : gm_cmd_receive(argv[2]);
    }
    fprintf(stderr, "unknown command: %s\n", cmd);
    return 1;
}
