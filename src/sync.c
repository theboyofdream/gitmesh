#include "gitmesh.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <lz4.h>

static bool parse_addr(const char *peer, char *ip, uint16_t *port) {
    int ip_a;
    int ip_b;
    int ip_c;
    int ip_d;
    int ip_port;
    if (sscanf(peer, "%d.%d.%d.%d:%d", &ip_a, &ip_b, &ip_c, &ip_d, &ip_port) == 5) {
        if (ip_a >= 0 && ip_a < 256 && ip_b >= 0 && ip_b < 256 && ip_c >= 0 && ip_c < 256 && ip_d >= 0 && ip_d < 256 && ip_port > 0 && ip_port < 65536) {
            snprintf(ip, 48, "%d.%d.%d.%d", ip_a, ip_b, ip_c, ip_d);
            *port = (uint16_t)ip_port;
            return true;
        }
    }
    return false;
}

static uint8_t *manifest_encode(const gm_manifest *manifest, size_t *outn) {
    size_t n = 4;
    for (size_t i = 0; i < manifest->n; i++)
        n += 2 + strlen(manifest->v[i].path) + crypto_generichash_BYTES + 8;
    uint8_t *buffer = gm_xmalloc(n);
    uint32_t count = (uint32_t)manifest->n;
    memcpy(buffer, &count, 4);
    size_t offset = 4;
    for (size_t i = 0; i < manifest->n; i++) {
        uint16_t path_len = (uint16_t)strlen(manifest->v[i].path);
        memcpy(buffer + offset, &path_len, 2);
        offset += 2;
        memcpy(buffer + offset, manifest->v[i].path, path_len);
        offset += path_len;
        memcpy(buffer + offset, manifest->v[i].hash, crypto_generichash_BYTES);
        offset += crypto_generichash_BYTES;
        memcpy(buffer + offset, &manifest->v[i].size, 8);
        offset += 8;
    }
    *outn = offset;
    return buffer;
}

static int manifest_decode(const uint8_t *data, size_t n, gm_manifest *manifest) {
    memset(manifest, 0, sizeof *manifest);
    if (n < 4) return -1;
    uint32_t count;
    memcpy(&count, data, 4);
    size_t offset = 4;
    for (uint32_t i = 0; i < count; i++) {
        if (offset + 2 > n) goto bad;
        uint16_t path_len;
        memcpy(&path_len, data + offset, 2);
        offset += 2;
        if (offset + (size_t)path_len + crypto_generichash_BYTES + 8 > n) goto bad;
        gm_entry e = {0};
        e.path = gm_xmalloc((size_t)path_len + 1);
        memcpy(e.path, data + offset, path_len);
        e.path[path_len] = 0;
        offset += path_len;
        memcpy(e.hash, data + offset, crypto_generichash_BYTES);
        offset += crypto_generichash_BYTES;
        memcpy(&e.size, data + offset, 8);
        offset += 8;
        gm_manifest_push(manifest, &e);
    }
    gm_manifest_sort(manifest);
    return 0;
bad:
    gm_manifest_free(manifest);
    return -1;
}

typedef struct {
    uint32_t *want;
    size_t n_want;
    char **del;
    size_t n_del;
    char **conflict;
    size_t n_conflict;
} gm_plan;

static void plan_free(gm_plan *plan) {
    free(plan->want);
    for (size_t i = 0; i < plan->n_del; i++) free(plan->del[i]);
    free(plan->del);
    for (size_t i = 0; i < plan->n_conflict; i++) free(plan->conflict[i]);
    free(plan->conflict);
    memset(plan, 0, sizeof *plan);
}

static void plan_push_conflict(gm_plan *plan, const char *path) {
    plan->conflict = gm_xrealloc(plan->conflict, (plan->n_conflict + 1) * sizeof(char *));
    plan->conflict[plan->n_conflict++] = gm_xstrdup(path);
}

static bool valid_rel_path(const char *path) {
    if (!path || !*path || path[0] == '/' || strstr(path, "..")) return false;
    for (const char *cursor = path; *cursor; cursor++)
        if (*cursor == '\\') return false;
    return true;
}

static void plan_compute(const gm_manifest *peer_manifest, const gm_manifest *my_manifest,
                         const gm_manifest *local_index, gm_plan *plan) {
    memset(plan, 0, sizeof *plan);
    for (size_t j = 0; j < peer_manifest->n; j++) {
        const gm_entry *peer_entry = &peer_manifest->v[j];
        if (!valid_rel_path(peer_entry->path)) {
            plan_push_conflict(plan, peer_entry->path);
            continue;
        }
        const gm_entry *my_entry = gm_manifest_find(my_manifest, peer_entry->path);
        if (!my_entry) {
            plan->want = gm_xrealloc(plan->want, (plan->n_want + 1) * sizeof(uint32_t));
            plan->want[plan->n_want++] = (uint32_t)j;
            continue;
        }
        if (memcmp(my_entry->hash, peer_entry->hash, crypto_generichash_BYTES) == 0) continue;
        const gm_entry *index_entry = gm_manifest_find(local_index, peer_entry->path);
        if (!index_entry ||
            memcmp(index_entry->hash, my_entry->hash, crypto_generichash_BYTES) == 0) {
            plan->want = gm_xrealloc(plan->want, (plan->n_want + 1) * sizeof(uint32_t));
            plan->want[plan->n_want++] = (uint32_t)j;
        } else {
            plan_push_conflict(plan, peer_entry->path);
        }
    }
    for (size_t i = 0; i < local_index->n; i++) {
        const gm_entry *index_entry = &local_index->v[i];
        if (gm_manifest_find(peer_manifest, index_entry->path)) continue;
        const gm_entry *my_entry = gm_manifest_find(my_manifest, index_entry->path);
        if (!my_entry ||
            memcmp(my_entry->hash, index_entry->hash, crypto_generichash_BYTES) == 0) {
            plan->del = gm_xrealloc(plan->del, (plan->n_del + 1) * sizeof(char *));
            plan->del[plan->n_del++] = gm_xstrdup(index_entry->path);
        } else {
            plan_push_conflict(plan, index_entry->path);
        }
    }
}

static int send_file(gm_sess *s, const char *root, const char *path,
                     const uint8_t hash[crypto_generichash_BYTES]) {
    char full[GM_PATH_MAX];
    if (snprintf(full, sizeof full, "%s/%s", root, path) >= (int)sizeof full)
        return -1;
    FILE *file = fopen(full, "rb");
    if (!file) return -1;

    size_t header_len = 2 + strlen(path) + 8 + crypto_generichash_BYTES;
    uint8_t *header = gm_xmalloc(header_len);
    uint16_t path_len = (uint16_t)strlen(path);
    fseek(file, 0, SEEK_END);
    long sz = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (sz < 0) {
        fclose(file);
        free(header);
        return -1;
    }

    uint64_t file_size = (uint64_t)sz;
    memcpy(header, &path_len, 2);
    memcpy(header + 2, path, path_len);
    memcpy(header + 2 + path_len, &file_size, 8);
    memcpy(header + 2 + path_len + 8, hash, crypto_generichash_BYTES);

    int result = gm_send_msg(s, GM_FILE_HDR, header, (uint32_t)header_len);
    free(header);
    if (result != 0) {
        fclose(file);
        return -1;
    }

    uint8_t *chunk_buffer = gm_xmalloc(GM_CHUNK);
    uint8_t *compressed_buffer = gm_xmalloc(LZ4_compressBound(GM_CHUNK));
    uint64_t sent_bytes = 0;
    while (sent_bytes < file_size) {
        size_t chunk_size =
            file_size - sent_bytes > GM_CHUNK ? GM_CHUNK : (size_t)(file_size - sent_bytes);
        if (fread(chunk_buffer, 1, chunk_size, file) != chunk_size) {
            result = -1;
            break;
        }
        int compressed_len = LZ4_compress_default((const char *)chunk_buffer,
                                                  (char *)compressed_buffer,
                                                  (int)chunk_size,
                                                  LZ4_compressBound((int)chunk_size));
        uint8_t *payload;
        uint32_t payload_size;
        if (compressed_len > 0 && (size_t)compressed_len + 5 < chunk_size) {
            payload_size = 5 + (uint32_t)compressed_len;
            payload = gm_xmalloc(payload_size);
            payload[0] = 1;
            memcpy(payload + 1, &compressed_len, 4);
            memcpy(payload + 5, compressed_buffer, (size_t)compressed_len);
        } else {
            uint32_t rawlen = (uint32_t)chunk_size;
            payload_size = 5 + rawlen;
            payload = gm_xmalloc(payload_size);
            payload[0] = 0;
            memcpy(payload + 1, &rawlen, 4);
            memcpy(payload + 5, chunk_buffer, chunk_size);
        }
        if (gm_send_msg(s, GM_FILE_DATA, payload, payload_size) != 0)
            result = -1;
        free(payload);
        if (result != 0) break;
        sent_bytes += chunk_size;
        printf("\r  %s %llu / %llu", path, (unsigned long long)sent_bytes,
               (unsigned long long)file_size);
        fflush(stdout);
    }
    printf("\n");
    fclose(file);
    free(chunk_buffer);
    free(compressed_buffer);
    return result;
}

static void print_progress(uint64_t received, uint64_t total) {
    printf("\r  %llu / %llu bytes", (unsigned long long)received,
           (unsigned long long)total);
    fflush(stdout);
}

static int finish_file(const char *root, const char *path,
                       const uint8_t hash[crypto_generichash_BYTES],
                       uint8_t *data, uint64_t size, gm_manifest *applied) {
    uint8_t computed_hash[crypto_generichash_BYTES];
    crypto_generichash(computed_hash, sizeof computed_hash, data, size, NULL, 0);
    if (memcmp(computed_hash, hash, sizeof computed_hash) != 0) {
        fprintf(stderr, "\nhash mismatch: %s\n", path);
        return -1;
    }
    if (gm_write_file_atomic(root, path, data, (size_t)size) != 0) {
        fprintf(stderr, "\nwrite failed: %s\n", path);
        return -1;
    }
    struct stat file_stat;
    char file_path[GM_PATH_MAX];
    snprintf(file_path, sizeof file_path, "%s/%s", root, path);
    gm_entry entry = {0};
    entry.path = gm_xstrdup(path);
    entry.size = size;
    memcpy(entry.hash, hash, crypto_generichash_BYTES);
    entry.mtime =
        stat(file_path, &file_stat) == 0 ? gm_st_mtime_ms(&file_stat) : gm_now_ms();
    gm_manifest_push(applied, &entry);
    return 0;
}

/* Receive FILE_HDR/DATA frames until DONE. Writes verified files atomically. */
static int recv_files(gm_sess *s, const char *root, gm_manifest *applied) {
    uint8_t msg_type = 0;
    uint8_t *payload = NULL;
    uint32_t msg_len = 0;

    char current_path[GM_PATH_MAX] = {0};
    uint8_t current_hash[crypto_generichash_BYTES] = {0};
    uint64_t current_size = 0;
    uint64_t received = 0;
    uint8_t *current_data = NULL;

    for (;;) {
        if (gm_recv_msg(s, &msg_type, &payload, &msg_len) != 0) goto fail;
        if (msg_type == GM_DONE) {
            free(payload);
            printf("\n");
            return 0;
        }
        if (msg_type == GM_ERR) {
            fprintf(stderr, "\npeer error: %.*s\n",
                    (int)(msg_len > 200 ? 200 : msg_len), (const char *)payload);
            free(payload);
            goto fail;
        }

        if (msg_type == GM_FILE_HDR) {
            if (received != current_size) goto fail;
            free(current_data);
            current_data = NULL;
            current_path[0] = 0;
            if (msg_len < 2u + crypto_generichash_BYTES + 8) goto fail;
            uint16_t path_len;
            memcpy(&path_len, payload, 2);
            if (2u + path_len + crypto_generichash_BYTES + 8 != msg_len ||
                path_len >= sizeof current_path)
                goto fail;
            memcpy(current_path, payload + 2, path_len);
            current_path[path_len] = 0;
            memcpy(&current_size, payload + 2 + path_len, 8);
            memcpy(current_hash, payload + 2 + path_len + 8, crypto_generichash_BYTES);
            if (!valid_rel_path(current_path)) goto fail;
            current_data = gm_xmalloc(current_size ? (size_t)current_size : 1);
            received = 0;
        } else if (msg_type == GM_FILE_DATA) {
            if (!current_data || msg_len < 5) goto fail;
            uint8_t compression_flag = payload[0];
            uint32_t compressed_len;
            memcpy(&compressed_len, payload + 1, 4);
            if ((size_t)compressed_len + 5 != msg_len) goto fail;
            if (compression_flag == 1) {
                if (received >= current_size) goto fail;
                int bytes_written =
                    LZ4_decompress_safe((const char *)payload + 5,
                                        (char *)current_data + received,
                                        (int)compressed_len,
                                        (int)(current_size - received));
                if (bytes_written < 0) goto fail;
                received += (uint64_t)bytes_written;
            } else {
                if (received + compressed_len > current_size) goto fail;
                memcpy(current_data + received, payload + 5, compressed_len);
                received += compressed_len;
            }
            print_progress(received, current_size);

            if (received == current_size) {
                if (finish_file(root, current_path, current_hash, current_data,
                                current_size, applied) != 0)
                    goto fail;
                free(current_data);
                current_data = NULL;
                current_path[0] = 0;
                printf("\n");
            }
        } else {
            goto fail;
        }
        free(payload);
        payload = NULL;
    }
fail:
    free(payload);
    free(current_data);
    return -1;
}

static void apply_deletes(const char *root, gm_plan *p, gm_manifest *idx) {
    for (size_t i = 0; i < p->n_del; i++) {
        char file_path[GM_PATH_MAX];
        snprintf(file_path, sizeof file_path, "%s/%s", root, p->del[i]);
        unlink(file_path);
        for (size_t j = 0; j < idx->n; j++) {
            if (strcmp(idx->v[j].path, p->del[i]) == 0) {
                free(idx->v[j].path);
                memmove(&idx->v[j], &idx->v[j + 1],
                        (idx->n - j - 1) * sizeof *idx->v);
                idx->n--;
                break;
            }
        }
        printf("deleted %s\n", p->del[i]);
    }
}

static int send_plan(gm_sess *s, const gm_plan *p) {
    size_t total_size = 12 + p->n_want * 4;
    for (size_t i = 0; i < p->n_del; i++) total_size += 2 + strlen(p->del[i]);
    for (size_t i = 0; i < p->n_conflict; i++)
        total_size += 2 + strlen(p->conflict[i]);
    uint8_t *buffer = gm_xmalloc(total_size);
    uint32_t want_count = (uint32_t)p->n_want;
    memcpy(buffer, &want_count, 4);
    size_t offset = 4;
    for (size_t i = 0; i < p->n_want; i++) {
        memcpy(buffer + offset, &p->want[i], 4);
        offset += 4;
    }
    uint32_t delete_count = (uint32_t)p->n_del;
    memcpy(buffer + offset, &delete_count, 4);
    offset += 4;
    for (size_t i = 0; i < p->n_del; i++) {
        uint16_t path_len = (uint16_t)strlen(p->del[i]);
        memcpy(buffer + offset, &path_len, 2);
        offset += 2;
        memcpy(buffer + offset, p->del[i], path_len);
        offset += path_len;
    }
    uint32_t conflict_count = (uint32_t)p->n_conflict;
    memcpy(buffer + offset, &conflict_count, 4);
    offset += 4;
    for (size_t i = 0; i < p->n_conflict; i++) {
        uint16_t path_len = (uint16_t)strlen(p->conflict[i]);
        memcpy(buffer + offset, &path_len, 2);
        offset += 2;
        memcpy(buffer + offset, p->conflict[i], path_len);
        offset += path_len;
    }
    return gm_send_msg(s, GM_SYNC_PLAN, buffer, (uint32_t)offset);
}

static void merge_index(gm_manifest *idx, const gm_manifest *applied) {
    for (size_t i = 0; i < applied->n; i++) {
        gm_entry *existing = gm_manifest_find(idx, applied->v[i].path);
        if (existing) {
            memcpy(existing->hash, applied->v[i].hash, crypto_generichash_BYTES);
            existing->size = applied->v[i].size;
            existing->mtime = applied->v[i].mtime;
        } else {
            gm_entry copy = applied->v[i];
            copy.path = gm_xstrdup(applied->v[i].path);
            gm_manifest_push(idx, &copy);
            gm_manifest_sort(idx);
        }
    }
}

static int parse_plan(const uint8_t *data, size_t n, gm_plan *plan) {
    memset(plan, 0, sizeof *plan);
    size_t offset = 0;
#define TAKE_U32(v)                                  \
    do {                                             \
        if (offset + 4 > n) return -1;               \
        memcpy(&(v), data + offset, 4);              \
        offset += 4;                                 \
    } while (0)

    uint32_t want_count_raw = 0;
    uint32_t delete_count_raw = 0;
    uint32_t conflict_count_raw = 0;
    TAKE_U32(want_count_raw);
    plan->want = NULL;
    plan->n_want = 0;
    if (want_count_raw > GM_FRAME_MAX / 4) return -1;
    for (uint32_t i = 0; i < want_count_raw; i++) {
        uint32_t value;
        TAKE_U32(value);
        plan->want = gm_xrealloc(plan->want, (plan->n_want + 1) * sizeof(uint32_t));
        plan->want[plan->n_want++] = value;
    }
    TAKE_U32(delete_count_raw);
    {
        plan->del = NULL;
        plan->n_del = 0;
        for (uint32_t i = 0; i < delete_count_raw; i++) {
            if (offset + 2 > n) return -1;
            uint16_t path_len;
            memcpy(&path_len, data + offset, 2);
            offset += 2;
            if (offset + path_len > n) return -1;
            char *path_string = gm_xmalloc((size_t)path_len + 1);
            memcpy(path_string, data + offset, path_len);
            path_string[path_len] = 0;
            offset += path_len;
            plan->del = gm_xrealloc(plan->del, (plan->n_del + 1) * sizeof(char *));
            plan->del[plan->n_del++] = path_string;
        }
    }
    TAKE_U32(conflict_count_raw);
    {
        plan->conflict = NULL;
        plan->n_conflict = 0;
        for (uint32_t i = 0; i < conflict_count_raw; i++) {
            if (offset + 2 > n) return -1;
            uint16_t path_len;
            memcpy(&path_len, data + offset, 2);
            offset += 2;
            if (offset + path_len > n) return -1;
            char *path_string = gm_xmalloc((size_t)path_len + 1);
            memcpy(path_string, data + offset, path_len);
            path_string[path_len] = 0;
            offset += path_len;
            plan->conflict =
                gm_xrealloc(plan->conflict, (plan->n_conflict + 1) * sizeof(char *));
            plan->conflict[plan->n_conflict++] = path_string;
        }
    }
#undef TAKE_U32
    return 0;
}

static bool confirm(const char *question) {
    printf("%s [y/N] ", question);
    fflush(stdout);
    char answer[16] = {0};
    if (!fgets(answer, sizeof answer, stdin)) return false;
    return answer[0] == 'y' || answer[0] == 'Y';
}

static void serve_session(int fd) {
    gm_sess *session = gm_serve(fd);
    if (!session) return;
    const uint8_t *peer_key = gm_sess_peer_pk(session);
    if (!gm_known_check(peer_key))
        gm_known_pin(NULL, peer_key, gm_sess_peer_name(session));

    uint8_t msg_type = 0;
    uint8_t *payload = NULL;
    uint32_t msg_len = 0;
    if (gm_recv_msg(session, &msg_type, &payload, &msg_len) != 0) {
        gm_close(session);
        return;
    }

    if (msg_type == GM_GET_MANIFEST) {
        free(payload);
    gm_manifest saved_index = {0};
    gm_manifest current_scan = {0};
        gm_index_load(".", &saved_index);
        gm_scan(".", &saved_index, &current_scan);
        size_t encoded_len = 0;
        uint8_t *encoded = manifest_encode(&current_scan, &encoded_len);
        gm_send_msg(session, GM_MANIFEST, encoded, (uint32_t)encoded_len);
        free(encoded);
        uint8_t reply_type = 0;
        uint8_t *reply_payload = NULL;
        uint32_t reply_len = 0;
        if (gm_recv_msg(session, &reply_type, &reply_payload, &reply_len) == 0 &&
            reply_type == GM_WANT) {
            uint32_t count = reply_len / 4;
            int result = 0;
            for (uint32_t i = 0; i < count && result == 0; i++) {
                uint32_t entry_index;
                memcpy(&entry_index, reply_payload + i * 4, 4);
                if (entry_index >= current_scan.n) result = -1;
                else
                    result = send_file(session, ".", current_scan.v[entry_index].path,
                                       current_scan.v[entry_index].hash);
            }
            if (result == 0) gm_send_msg(session, GM_DONE, "complete", 8);
            else gm_send_msg(session, GM_ERR, "transfer failed", 15);
            free(reply_payload);
        } else {
            free(reply_payload);
        }
        gm_manifest_free(&saved_index);
        gm_manifest_free(&current_scan);
    } else if (msg_type == GM_PUSH_MANIFEST) {
        gm_manifest peer_manifest = {0};
        if (manifest_decode(payload, msg_len, &peer_manifest) != 0) {
            free(payload);
            gm_send_msg(session, GM_ERR, "bad manifest", 12);
            gm_close(session);
            return;
        }
        free(payload);
        gm_manifest saved_index = {0};
        gm_manifest current_scan = {0};
        gm_index_load(".", &saved_index);
        gm_scan(".", &saved_index, &current_scan);
        gm_plan plan;
        plan_compute(&peer_manifest, &current_scan, &saved_index, &plan);
        send_plan(session, &plan);

        gm_manifest applied = {0};
        if (recv_files(session, ".", &applied) == 0) {
            apply_deletes(".", &plan, &saved_index);
            merge_index(&saved_index, &applied);
            gm_index_save(".", &saved_index);
            char msg[128];
            snprintf(msg, sizeof msg, "%zu file(s) applied", applied.n);
            gm_send_msg(session, GM_DONE, msg, (uint32_t)strlen(msg));
        } else {
            gm_send_msg(session, GM_ERR, "transfer failed", 15);
        }
        plan_free(&plan);
        gm_manifest_free(&peer_manifest);
        gm_manifest_free(&saved_index);
        gm_manifest_free(&current_scan);
        gm_manifest_free(&applied);
    } else {
        free(payload);
        gm_send_msg(session, GM_ERR, "unknown request", 15);
    }
    gm_close(session);
}

int gm_cmd_share(void) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    if (gm_sock_init() != 0) gm_die("socket init failed");
    gm_ident id;
    gm_ident_load(&id);
    uint16_t tcp_port = gm_env_tcp_port();
    int listen_fd = gm_listen(tcp_port);
    if (listen_fd < 0) gm_die("cannot listen on TCP %d", tcp_port);
    char display[GM_NAME_MAX];
    gm_ident_display(&id, display);
    printf("gitmesh %s — sharing '%s'\n", GM_VERSION, display);
    int64_t last_announce = 0;
    for (;;) {
        int64_t now = gm_now_ms();
        if (now - last_announce >= 2000) {
            gm_disco_run(&id, tcp_port);
            last_announce = now;
        }
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        struct timeval tv = {.tv_sec = 0, .tv_usec = 300000};
        if (select(listen_fd + 1, &rfds, NULL, NULL, &tv) > 0) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd >= 0)
                serve_session(client_fd);
        }
    }
}

static void resolve_or_die(const gm_ident *id, const char *peer,
                           char *ip, uint16_t *port, uint8_t *peer_key) {
    if (parse_addr(peer, ip, port)) {
        memset(peer_key, 0, crypto_sign_PUBLICKEYBYTES);
        return;
    }
    printf("looking for %s...\n", peer);
    if (gm_disco_resolve(id, peer, ip, port, peer_key) != 0)
        gm_die("peer '%s' not found online", peer);
}

static void project_root(char *root, size_t n) {
    if (!getcwd(root, n)) gm_die("cannot determine working directory");
}

int gm_cmd_send(const char *peer) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    gm_sock_init();
    gm_ident identity;
    gm_ident_load(&identity);
    char ip[48];
    uint16_t port = gm_env_tcp_port();
    uint8_t peer_key[crypto_sign_PUBLICKEYBYTES];
    resolve_or_die(&identity, peer, ip, &port, peer_key);
    if (peer_key[0] || peer_key[1]) {
        if (!gm_known_check(peer_key)) gm_known_pin(NULL, peer_key, peer);
    }

    char root[GM_PATH_MAX];
    project_root(root, sizeof root);

    gm_manifest saved_index = {0};
    gm_manifest current_scan = {0};
    gm_index_load(root, &saved_index);
    gm_scan(root, &saved_index, &current_scan);
    size_t added = 0;
    size_t modified = 0;
    size_t deleted = 0;
    gm_diff(&saved_index, &current_scan, &added, &modified, &deleted);
    printf("\n%zu file(s) changed\n%zu file(s) added\n%zu file(s) deleted\n",
           modified, added, deleted);
    if (added + modified + deleted == 0) {
        printf("nothing to send\n");
        gm_manifest_free(&saved_index);
        gm_manifest_free(&current_scan);
        return 0;
    }
    if (!confirm("send?")) {
        printf("aborted\n");
        gm_manifest_free(&saved_index);
        gm_manifest_free(&current_scan);
        return 1;
    }

    printf("\nconnecting %s (%s:%u)\n", peer, ip, port);
    gm_sess *session = gm_connect(ip, port);
    {
        const uint8_t *session_peer_key = gm_sess_peer_pk(session);
        if (!gm_known_check(session_peer_key))
            gm_known_pin(NULL, session_peer_key, peer);
    }
    size_t encoded_len = 0;
    uint8_t *encoded = manifest_encode(&current_scan, &encoded_len);
    int result = gm_send_msg(session, GM_PUSH_MANIFEST, encoded, (uint32_t)encoded_len);
    free(encoded);
    if (result != 0) {
        gm_close(session);
        gm_die("connection lost");
    }

    uint8_t msg_type = 0;
    uint8_t *payload = NULL;
    uint32_t msg_len = 0;
    if (gm_recv_msg(session, &msg_type, &payload, &msg_len) != 0 ||
        msg_type != GM_SYNC_PLAN) {
        gm_close(session);
        gm_die("peer did not accept manifest");
    }
    gm_plan plan;
    if (parse_plan(payload, msg_len, &plan) != 0) {
        free(payload);
        gm_close(session);
        gm_die("bad plan from peer");
    }
    free(payload);

    for (size_t i = 0; i < plan.n_conflict; i++)
        fprintf(stderr, "conflict (skipped): %s\n", plan.conflict[i]);
    printf("%zu file(s) to transfer\n\n", plan.n_want);

    for (size_t i = 0; i < plan.n_want && result == 0; i++) {
        uint32_t entry_index = plan.want[i];
        if (entry_index >= current_scan.n) {
            result = -1;
            break;
        }
        result = send_file(session, root, current_scan.v[entry_index].path,
                           current_scan.v[entry_index].hash);
    }
    if (result == 0)
        result = gm_send_msg(session, GM_DONE, "", 0);
    if (result == 0 && gm_recv_msg(session, &msg_type, &payload, &msg_len) == 0 &&
        msg_type == GM_DONE) {
        printf("peer: %.*s\n", (int)(msg_len > 100 ? 100 : msg_len),
               (const char *)payload);
        free(payload);
        gm_index_save(root, &current_scan);
    } else if (result == 0) {
        fprintf(stderr, "transfer incomplete\n");
    }
    plan_free(&plan);
    gm_close(session);
    gm_manifest_free(&saved_index);
    gm_manifest_free(&current_scan);
    return result == 0 ? 0 : 1;
}

int gm_cmd_receive(const char *peer) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    gm_sock_init();
    gm_ident identity;
    gm_ident_load(&identity);
    char ip[48];
    uint16_t port = gm_env_tcp_port();
    uint8_t peer_key[crypto_sign_PUBLICKEYBYTES];
    resolve_or_die(&identity, peer, ip, &port, peer_key);
    if (peer_key[0] || peer_key[1]) {
        if (!gm_known_check(peer_key)) gm_known_pin(NULL, peer_key, peer);
    }

    char root[GM_PATH_MAX];
    project_root(root, sizeof root);

    printf("\nconnecting %s (%s:%u)\n", peer, ip, port);
    gm_sess *session = gm_connect(ip, port);
    {
        const uint8_t *session_peer_key = gm_sess_peer_pk(session);
        if (!gm_known_check(session_peer_key))
            gm_known_pin(NULL, session_peer_key, peer);
    }
    if (gm_send_msg(session, GM_GET_MANIFEST, "", 0) != 0) {
        gm_close(session);
        gm_die("connection lost");
    }

    uint8_t msg_type = 0;
    uint8_t *payload = NULL;
    uint32_t msg_len = 0;
    if (gm_recv_msg(session, &msg_type, &payload, &msg_len) != 0 ||
        msg_type != GM_MANIFEST) {
        gm_close(session);
        gm_die("could not fetch peer manifest");
    }
    gm_manifest peer_manifest = {0};
    if (manifest_decode(payload, msg_len, &peer_manifest) != 0) {
        free(payload);
        gm_close(session);
        gm_die("bad manifest from peer");
    }
    free(payload);

    gm_manifest saved_index = {0};
    gm_manifest current_scan = {0};
    gm_index_load(root, &saved_index);
    gm_scan(root, &saved_index, &current_scan);
    gm_plan plan;
    plan_compute(&peer_manifest, &current_scan, &saved_index, &plan);

    size_t new_count = 0;
    for (size_t i = 0; i < plan.n_want; i++) {
        uint32_t want_index = plan.want[i];
        if (want_index < peer_manifest.n &&
            !gm_manifest_find(&current_scan, peer_manifest.v[want_index].path))
            new_count++;
    }
    printf("\n%zu file(s) to add/update\n%zu new file(s)\n%zu deletion(s)\n",
           plan.n_want, new_count, plan.n_del);
    for (size_t i = 0; i < plan.n_conflict; i++)
        fprintf(stderr, "conflict (kept local): %s\n", plan.conflict[i]);
    if (plan.n_want == 0 && plan.n_del == 0) {
        printf("already up to date\n");
        plan_free(&plan);
        gm_manifest_free(&peer_manifest);
        gm_manifest_free(&saved_index);
        gm_manifest_free(&current_scan);
        gm_close(session);
        return 0;
    }
    if (!confirm("apply changes from peer?")) {
        printf("aborted\n");
        plan_free(&plan);
        gm_manifest_free(&peer_manifest);
        gm_manifest_free(&saved_index);
        gm_manifest_free(&current_scan);
        gm_close(session);
        return 1;
    }

    size_t buffer_size = 4 + plan.n_want * 4;
    uint8_t *buffer = gm_xmalloc(buffer_size);
    uint32_t want_count = (uint32_t)plan.n_want;
    memcpy(buffer, &want_count, 4);
    for (size_t i = 0; i < plan.n_want; i++)
        memcpy(buffer + 4 + i * 4, &plan.want[i], 4);
    int result = gm_send_msg(session, GM_WANT, buffer, (uint32_t)(4 + plan.n_want * 4));
    free(buffer);

    gm_manifest applied = {0};
    if (result == 0)
        result = recv_files(session, root, &applied);
    if (result == 0) {
        apply_deletes(root, &plan, &saved_index);
        merge_index(&saved_index, &applied);
        gm_index_save(root, &saved_index);
        printf("done: %zu applied\n", applied.n);
    } else {
        fprintf(stderr, "transfer incomplete\n");
    }
    plan_free(&plan);
    gm_manifest_free(&peer_manifest);
    gm_manifest_free(&saved_index);
    gm_manifest_free(&current_scan);
    gm_manifest_free(&applied);
    gm_close(session);
    return result == 0 ? 0 : 1;
}
