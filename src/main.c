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
        char fp[9];
        gm_hex(fp, peers[i].sign_pk + 24, 4);
        printf("  %c %-20s %-15s ~%s\n", '*', peers[i].name, peers[i].ip, fp);
    }
    return 0;
}

static int cmd_status(void) {
    gm_sock_init();
    gm_ident id;
    gm_ident_load(&id);
    char pkhex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    gm_hex(pkhex, id.sign_pk, crypto_sign_PUBLICKEYBYTES);
    char root[GM_PATH_MAX];
    if (!getcwd(root, sizeof root)) gm_die("cannot determine working directory");

    printf("gitmesh %s\n", GM_VERSION);
    printf("device:   %s\n", id.name);
    printf("identity: %.16s...\n", pkhex);
    printf("project:  %s\n", root);

    gm_manifest old = {0}, cur = {0};
    int have_index = gm_index_load(root, &old) == 0;
    gm_scan(root, &old, &cur);
    printf("indexed:  %s (%zu files)\n", have_index ? "yes" : "no", old.n);
    printf("current:  %zu files\n", cur.n);
    if (have_index) {
        size_t added = 0, modified = 0, deleted = 0;
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
               "  receive <peer>   pull peer's changes into this project\n");
        return argc < 2 ? 1 : 0;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "peers") == 0) return cmd_peers();
    if (strcmp(cmd, "status") == 0) return cmd_status();
    if (strcmp(cmd, "share") == 0) return gm_cmd_share();
    if ((strcmp(cmd, "send") == 0 || strcmp(cmd, "receive") == 0)) {
        if (argc < 3)
            gm_die("usage: gitmesh %s <peer>", cmd);
        return strcmp(cmd, "send") == 0 ? gm_cmd_send(argv[2])
                                        : gm_cmd_receive(argv[2]);
    }
    fprintf(stderr, "unknown command: %s\n", cmd);
    return 1;
}
