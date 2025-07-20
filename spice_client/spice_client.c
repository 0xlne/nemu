#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <spice/protocol.h>

#define SPICE_ATTR_PACKED __attribute__((__packed__))

typedef struct spice_conn {
    int sd;
    uint64_t serial;
} spice_conn_t;

typedef SpiceLinkHeader spice_link_header_t;
typedef SpiceLinkMess spice_link_mess_t;
typedef SpiceLinkReply spice_link_reply_t;
typedef SpiceDataHeader spice_data_header_t;
typedef SpiceMiniDataHeader spice_mini_data_header_t;

typedef struct SPICE_ATTR_PACKED SpiceImageDescriptor {
    uint64_t id;
    uint8_t type;
    uint8_t flags;
    uint32_t width;
    uint32_t height;
} spice_image_descriptor_t;

typedef struct SPICE_ATTR_PACKED SpicePalette {
    uint64_t unique;
    uint16_t num_ents;
    uint32_t ents[];
} spice_palette_t;

typedef struct SPICE_ATTR_PACKED SpiceBitmap {
    uint8_t format;
    uint8_t flags;
    uint32_t x;
    uint32_t y;
    uint32_t stride;
    spice_palette_t *palette;
    uint64_t palette_id;
    uint8_t *data;
} spice_bitmap_t;

typedef struct SPICE_ATTR_PACKED SpiceImage {
    spice_image_descriptor_t descriptor;
    spice_bitmap_t bitmap;
} spice_image_t;

typedef struct SPICE_ATTR_PACKED SpiceRect {
    int32_t top;
    int32_t left;
    int32_t bottom;
    int32_t right;
} spice_rect_t;

typedef struct SPICE_ATTR_PACKED SpiceClipRects {
    uint32_t num_rects;
    spice_rect_t rects[];
} spice_clip_rects_t;

typedef struct SPICE_ATTR_PACKED SpiceClip {
    uint8_t type;
    spice_clip_rects_t *rects;
} spice_clip_t;

typedef struct SPICE_ATTR_PACKED SpiceMsgDisplayBase {
    uint32_t surface_id;
    spice_rect_t box;
    spice_clip_t clip;
} spice_msg_display_base_t;

typedef struct SPICE_ATTR_PACKED SpiceMsgSurfaceCreate {
    uint32_t surface_id;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint32_t flags;
} spice_msg_surface_create_t;

typedef struct SPICE_ATTR_PACKED SpicePoint {
    int32_t x;
    int32_t y;
} spice_point_t;

typedef struct SPICE_ATTR_PACKED SpiceQMask {
    uint8_t flags;
    spice_point_t pos;
    spice_image_t *bitmap;
} spice_qmask_t;

typedef struct SPICE_ATTR_PACKED SpiceCopy {
    spice_image_t *src_bitmap;
    struct SPICE_ATTR_PACKED {
        spice_rect_t src_area;
        uint16_t rop_descriptor;
        uint8_t scale_mode;
    } meta;
    spice_qmask_t mask;
} spice_copy_t;

typedef struct SPICE_ATTR_PACKED SpiceMsgDisplayDrawCopy {
    spice_msg_display_base_t base;
    spice_copy_t data;
} spice_msg_display_draw_copy_t;

typedef struct SPICE_ATTR_PACKED SpiceMsgMainInit {
    uint32_t session_id;
    uint32_t display_channels_hint;
    uint32_t supported_mouse_modes;
    uint32_t current_mouse_mode;
    uint32_t agent_connected;
    uint32_t agent_tokens;
    uint32_t multi_media_time;
    uint32_t ram_hint;
} spice_msg_main_init_t;

typedef struct SPICE_ATTR_PACKED SpiceMsgDisplayMode {
    uint32_t width;
    uint32_t height;
    uint32_t depth;
} spice_msg_display_mode;

typedef struct SPICE_ATTR_PACKED SpiceMsgcDisplayInit {
    uint8_t cache_id;
    int64_t cache_size;
    uint8_t dictionary_id;
    uint32_t dictionary_window_size;
} spice_msgc_display_init;

typedef struct SPICE_ATTR_PACKED SpiceMsgcPreferredCompression {
    uint8_t image_compression;
} spice_msgc_preferred_compression;

typedef struct __attribute((packed))__
{
    uint16_t type;
    uint32_t size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t offset;
    uint32_t dib_header_size;
    int32_t width_px;
    int32_t height_px;
    uint16_t num_planes;
    uint16_t bits_per_pixel;
    uint32_t compression;
    uint32_t image_size_bytes;
    int32_t x_resolution_ppm;
    int32_t y_resolution_ppm;
    uint32_t num_colors;
    uint32_t important_colors;
} bmp_header_t;

int read_spice_packet(int sd, uint8_t *buf, ssize_t len);
static bool init_channel(int sd, uint32_t session_id, uint8_t channel_type,
        uint32_t common_caps, uint32_t channel_caps);
static void spice_copy_image(const uint8_t *src, uint8_t **srcp,
        spice_image_t **img);
static void spice_copy_palette(const uint8_t *src, uint8_t **srcp,
        spice_palette_t **dst, uint64_t *dst_id);
static void spice_copy_bitmap(const uint8_t *src, const spice_image_t *img,
        spice_bitmap_t *dst);
static void write_bmp_header(FILE *fp, unsigned int width, unsigned int height);
static void write_bmp_payload(FILE *fp, spice_bitmap_t *bmp,
        spice_msg_display_draw_copy_t *draw,
        unsigned int width, 
        unsigned int height);

static int spice_connect(void) {
    struct sockaddr_in spice_saddr;
    int sd = -1, opt = 1;

    memset(&spice_saddr, 0, sizeof(spice_saddr));

    spice_saddr.sin_family = AF_INET;
    spice_saddr.sin_port = htons(5900);
    inet_pton(AF_INET, "127.0.0.1", &spice_saddr.sin_addr);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    if (connect(sd, (struct sockaddr *) &spice_saddr,
                sizeof(spice_saddr)) < 0) {
        fprintf(stderr, "connect: %s\n", strerror(errno));
        exit(1);
    }

    return sd;
}

unsigned char *encrypt_password(const unsigned char *key, size_t *encrypted_len)
{
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &key, SPICE_TICKET_PUBKEY_BYTES);
    if (!pkey) {
        fprintf(stderr, "Error reading public key: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    PEM_write_PUBKEY(stdout, pkey);

    const char *password = "password";
    size_t password_len = strlen(password);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt_init: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha1()) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt_init: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha1()) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0);

    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_len,
                (unsigned char *)password, password_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        goto out;
    }

    unsigned char *encrypted = malloc(*encrypted_len);
    if (!encrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        goto out;
    }

    if (EVP_PKEY_encrypt(ctx, encrypted, encrypted_len,
                (unsigned char *)password, password_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_encrypt: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
    }

out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return encrypted;
}

static bool spice_channel_main(int sd, uint32_t *session_id)
{
    uint32_t common_caps = 0;
    uint32_t channel_caps = 0;
    spice_mini_data_header_t data_hdr = {0};
    spice_msg_main_init_t main_init_msg = {0};
    
    common_caps |= (1 << SPICE_COMMON_CAP_MINI_HEADER);

    if (init_channel(sd, 0, SPICE_CHANNEL_MAIN,
            common_caps, channel_caps) == false) {
        return false;
    }

    read_spice_packet(sd, (uint8_t *) &data_hdr, sizeof(data_hdr));
    printf("type: %u, size: %u\n",
            data_hdr.type, data_hdr.size);

    if (data_hdr.type != SPICE_MSG_MAIN_INIT) {
        fprintf(stderr, "Unexpected type: %u\n", data_hdr.type);
        return false;
    }

    read_spice_packet(sd, (uint8_t *) &main_init_msg, sizeof(main_init_msg));
    printf("session_id: %u\n", main_init_msg.session_id);
    *session_id = main_init_msg.session_id;

    return true;
}

static bool spice_channel_display(int sd, uint32_t session_id)
{
    uint32_t common_caps = 0;
    uint32_t channel_caps = 0;

    common_caps |= (1 << SPICE_COMMON_CAP_MINI_HEADER);
    channel_caps |= (1 << SPICE_DISPLAY_CAP_PREF_COMPRESSION);

    if (init_channel(sd, session_id, SPICE_CHANNEL_DISPLAY,
            common_caps, channel_caps) == false) {
        return false;
    }

    char cache_buf[sizeof(spice_mini_data_header_t) +
        sizeof(spice_msgc_display_init)] = {0};
    spice_mini_data_header_t data_hdr = {0};
    spice_msgc_display_init display_init = {0};
    data_hdr.type = SPICE_MSGC_DISPLAY_INIT;
    data_hdr.size = sizeof(spice_msgc_display_init);
    memcpy(cache_buf, &data_hdr, sizeof(data_hdr));
    memcpy(cache_buf + sizeof(spice_mini_data_header_t),
            &display_init, sizeof(display_init));
    send(sd, cache_buf, sizeof(cache_buf), 0);

    char comp_buf[sizeof(spice_mini_data_header_t) +
        sizeof(spice_msgc_preferred_compression)] = {0};
    data_hdr.type = SPICE_MSGC_DISPLAY_PREFERRED_COMPRESSION;
    data_hdr.size = sizeof(spice_msgc_preferred_compression);
    spice_msgc_preferred_compression comp = {0};
    comp.image_compression = SPICE_IMAGE_COMPRESSION_OFF;
    memcpy(comp_buf, &data_hdr, sizeof(data_hdr));
    memcpy(comp_buf + sizeof(spice_mini_data_header_t),
            &comp, sizeof(comp));
    send(sd, comp_buf, sizeof(comp_buf), 0);
    
    memset(&data_hdr, 0, sizeof(data_hdr));
    recv(sd, &data_hdr, sizeof(data_hdr), 0);
    printf("type: %u, size: %u -> ХЗ что это за пакет\n",
            data_hdr.type, data_hdr.size);

    void *data = malloc(data_hdr.size);
    recv(sd, data, data_hdr.size, 0);

    memset(&data_hdr, 0, sizeof(data_hdr));
    recv(sd, &data_hdr, sizeof(data_hdr), 0);
    printf("type: %u, size: %u -> SPICE_MSG_DISPLAY_INVAL_ALL_PALETTES\n",
            data_hdr.type, data_hdr.size);

    memset(&data_hdr, 0, sizeof(data_hdr));
    recv(sd, &data_hdr, sizeof(data_hdr), 0);
    printf("type: %u, size: %u -> SPICE_MSG_DISPLAY_SURFACE_CREATE\n",
            data_hdr.type, data_hdr.size);

    free(data);
    data = malloc(data_hdr.size);
    read_spice_packet(sd, data, data_hdr.size);

    spice_msg_surface_create_t *surface_create = data;
    printf("surface_id: %u, height: %u, width: %u, format: %u\n",
            surface_create->surface_id,
            surface_create->height, surface_create->width,
            surface_create->format);
    uint32_t width = surface_create->width;
    uint32_t height = surface_create->height;

    memset(&data_hdr, 0, sizeof(data_hdr));
    recv(sd, &data_hdr, sizeof(data_hdr), 0);
    printf("type: %u, size: %u -> SPICE_MSG_DISPLAY_DRAW_COPY\n",
            data_hdr.type, data_hdr.size);

    free(data);
    data = malloc(data_hdr.size);
    read_spice_packet(sd, data, data_hdr.size);
    uint8_t *src = data;

    spice_msg_display_draw_copy_t draw = {0};
    memcpy(&draw.base.surface_id, src, sizeof(draw.base.surface_id));
    src += sizeof(draw.base.surface_id);
    memcpy(&draw.base.box, src, sizeof(draw.base.box));
    src += sizeof(draw.base.box);
    memcpy(&draw.base.clip.type, src, sizeof(draw.base.clip.type));
    src += sizeof(draw.base.clip.type);
    if (draw.base.clip.type == SPICE_CLIP_TYPE_RECTS) {
        printf("clip type is SPICE_CLIP_TYPE_RECTS\n");
        draw.base.clip.rects = (spice_clip_rects_t *) src;
        src += sizeof(draw.base.clip.rects->num_rects);
        src += draw.base.clip.rects->num_rects * sizeof(spice_rect_t);
    } else {
        printf("clip type is not SPICE_CLIP_TYPE_RECTS: %u\n", draw.base.clip.type);
    }

    spice_copy_image(data, &src, &draw.data.src_bitmap);
    
    if (!draw.data.src_bitmap) {
        printf("Image is not bitmaps!\n");
    } else {
        printf("Image OK: %ux%u\n",
                draw.data.src_bitmap->descriptor.width,
                draw.data.src_bitmap->descriptor.height);
    }

    memcpy(&draw.data.meta, src, sizeof(draw.data.meta));
    src += sizeof(draw.data.meta);

    int mask_copy_len = sizeof(draw.data.mask.flags) + sizeof(draw.data.mask.pos);
    memcpy(&draw.data.mask, src, mask_copy_len);
    src += mask_copy_len;

    spice_copy_image(data, &src, &draw.data.mask.bitmap);

    printf("Img type: %u\n", draw.data.src_bitmap->descriptor.type);
    spice_bitmap_t bmp = {0};
    FILE *fp = fopen("/tmp/qemu.bmp", "wb");
    spice_copy_bitmap(data, draw.data.src_bitmap, &bmp);
    write_bmp_header(fp, width, height);
    write_bmp_payload(fp, &bmp, &draw, width, height);

    return true;
}

static bool
init_channel(int sd, uint32_t session_id, uint8_t channel_type,
        uint32_t common_caps, uint32_t channel_caps)
{
    uint32_t magic = SPICE_MAGIC;
    unsigned char msg[sizeof(spice_link_header_t) +
        sizeof(spice_link_mess_t) + 2 * sizeof(uint32_t)] = {0};
    unsigned char reply[sizeof(spice_link_header_t) +
        sizeof(spice_link_reply_t)] = {0};
    unsigned char *pmsg = msg;
    spice_link_header_t spice_link_hdr;
    spice_link_mess_t spice_link_mess;
    spice_link_reply_t spice_link_reply;
    size_t cl_caps_len = 0;
    ssize_t srv_caps_len;
    unsigned char *srv_caps_buf;

    if (common_caps) {
        cl_caps_len = sizeof(uint32_t);
    }

    if (channel_caps) {
        cl_caps_len = sizeof(uint32_t) * 2;
    }

    memset(&spice_link_hdr, 0, sizeof(spice_link_hdr));
    memset(&spice_link_mess, 0, sizeof(spice_link_mess));
    memset(&spice_link_reply, 0, sizeof(spice_link_reply));

    spice_link_hdr.magic = magic;
    spice_link_hdr.major_version = SPICE_VERSION_MAJOR;
    spice_link_hdr.minor_version = SPICE_VERSION_MINOR;
    spice_link_hdr.size = sizeof(spice_link_mess) + cl_caps_len;

    memcpy(pmsg, &spice_link_hdr, sizeof(spice_link_hdr));
    pmsg += sizeof(spice_link_hdr);

    spice_link_mess.channel_type = channel_type;
    spice_link_mess.connection_id = session_id;
    spice_link_mess.caps_offset = sizeof(spice_link_mess);
    if (common_caps) {
        spice_link_mess.num_common_caps = 1;
    }
    if (channel_caps) {
        spice_link_mess.num_channel_caps = 1;
    }
    memcpy(pmsg, &spice_link_mess, sizeof(spice_link_mess));
    if (common_caps) {
        memcpy(pmsg + sizeof(spice_link_mess),
                &common_caps, sizeof(common_caps));
    }
    if (channel_caps) {
        memcpy(pmsg + sizeof(spice_link_mess) + sizeof(common_caps),
                &channel_caps, sizeof(channel_caps));
    }

    send(sd, msg, sizeof(spice_link_hdr) +
            sizeof(spice_link_mess) + cl_caps_len, 0);
    recv(sd, &reply, sizeof(reply), 0);
    memcpy(&spice_link_hdr, reply, sizeof(spice_link_hdr));
    memcpy(&spice_link_reply, reply + sizeof(spice_link_hdr),
            sizeof(spice_link_reply));

    if (spice_link_reply.error != SPICE_LINK_ERR_OK) {
        fprintf(stderr, "bad reply: %d\n", spice_link_reply.error);
        return false;
    }

    srv_caps_len = spice_link_hdr.size - spice_link_reply.caps_offset;
    srv_caps_buf = malloc(srv_caps_len);
    read_spice_packet(sd, srv_caps_buf, srv_caps_len);
    free(srv_caps_buf);

    const unsigned char *key = spice_link_reply.pub_key;
    size_t encrypted_len;
    unsigned char *encrypted = encrypt_password(key, &encrypted_len);
    if (!encrypted) {
        return false;
    }
    send(sd, encrypted, encrypted_len, 0);
    free(encrypted);

    uint32_t result = 0;
    recv(sd, &result, sizeof(result), 0);
    if (result != SPICE_LINK_ERR_OK) {
        fprintf(stderr, "Ret code: %u\n", result);
        return false;
    }

    return true;
}

static void
spice_copy_image(const uint8_t *src,
        uint8_t **srcp, spice_image_t **img) {
    uint32_t offset = 0;
    
    memcpy(&offset, *srcp, sizeof(offset));
    printf("%s: offset: %d\n", __func__, offset);
    *srcp += sizeof(offset);
    *img = (spice_image_t *) (offset > 0 ? src + offset : NULL);
}

static void
spice_copy_palette(const uint8_t *src, uint8_t **srcp,
    spice_palette_t **dst, uint64_t *dst_id) {
    uint32_t offset = 0;
    
    memcpy(&offset, *srcp, sizeof(offset));
    printf("%s: offset: %d\n", __func__, offset);
    *srcp += sizeof(offset);

    if (offset) {
        *dst = (spice_palette_t *) src + offset;
        memcpy(dst_id, *srcp, sizeof(*dst_id));
        *srcp += sizeof(*dst_id);

        return;
    }

    *dst = NULL;
    *dst_id = 0;
}

static void
spice_copy_bitmap(const uint8_t *src, const spice_image_t *img,
    spice_bitmap_t *dst) {
    uint8_t *p = (uint8_t *) &img->bitmap;

    int len =
        sizeof(dst->format) +
        sizeof(dst->flags) +
        sizeof(dst->x) +
        sizeof(dst->y) +
        sizeof(dst->stride);

    memcpy(dst, p, len);
    p += len;

    spice_copy_palette(src, &p, &dst->palette, &dst->palette_id);
    dst->data = p;
}

static void write_bmp_header(
        FILE *fp,
        unsigned int width, 
        unsigned int height)
{
    bmp_header_t hdr = {
        .type = 0x4d42,
        .size = sizeof(bmp_header_t) + height * width * 4,
        .offset = sizeof(bmp_header_t),
        .dib_header_size = 40,
        .width_px = width,
        .height_px = height,
        .num_planes = 1,
        .bits_per_pixel = 32,
        .image_size_bytes = height * width * 4,
        .x_resolution_ppm = 0,
        .y_resolution_ppm = 0,
    };

    fseek(fp, 0, SEEK_SET);
    fwrite(&hdr, sizeof(hdr), 1, fp);
    fflush(fp);
}

static void write_bmp_payload(
        FILE *fp,
        spice_bitmap_t *bmp,
        spice_msg_display_draw_copy_t *draw,
        unsigned int width, 
        unsigned int height)
{
    bool top_down = bmp->flags & SPICE_BITMAP_FLAGS_TOP_DOWN;

    printf("XXX: x: %d y: %d w: %d h: %d stride: %d height: %u\n",
            draw->base.box.top, draw->base.box.left, width, height, bmp->stride, bmp->y);

    if (top_down) {
        uint8_t *src = bmp->data;
        printf("%s: top_down %u\n", __func__, bmp->y);
        
        for (uint32_t n = 0; n < bmp->y; ++n) {
            int dst = (width * 4 * (height - (draw->base.box.top + n))) +
                draw->base.box.left * 4;
            fseek(fp, sizeof(bmp_header_t) + dst, SEEK_SET);
            fwrite(src, bmp->stride, 1, fp);
            src += bmp->stride;
        }
        goto out;
    }

    printf("%s: !top_down\n", __func__);
    uint8_t *src = bmp->data + bmp->y * bmp->stride;
    for (uint32_t n = 0; n < bmp->y; ++n) {
        int dst = (width * 4 * (height - (draw->base.box.top + n))) +
            draw->base.box.left * 4;
        fseek(fp, sizeof(bmp_header_t) + dst, SEEK_SET);
        src -= bmp->stride;
        fwrite(src, bmp->stride, 1, fp);
    }
out:
    fflush(fp);

}

int read_spice_packet(int sd, uint8_t *buf, ssize_t len)
{
    ssize_t remain = len;

    while (remain) {
        ssize_t recv_len = recv(sd, buf, remain, 0);
        if (recv_len == 0) { /* end-of-file */
            printf("%s: no data...\n", __func__);
            return -1;
        }
        if (recv_len < 0) {
            printf("%s: error...\n", __func__);
            return -2;
        }
        buf += recv_len;
        remain -= recv_len;
        printf("%s: got %ld len of %ld\n", __func__, recv_len, len);
    }

    return 0;
}

static void
send_key(int sd, uint64_t serial, const unsigned char *keycode, bool up)
{
    spice_data_header_t input_data_hdr = {0};
    unsigned char buf[sizeof(input_data_hdr) + 4] = {0};

    input_data_hdr.serial = serial;
    input_data_hdr.type = up ?
        SPICE_MSGC_INPUTS_KEY_UP : SPICE_MSGC_INPUTS_KEY_DOWN;
    input_data_hdr.size = 4;

    memcpy(buf, &input_data_hdr, sizeof(input_data_hdr));
    memcpy(buf + sizeof(input_data_hdr), keycode, 4);
    send(sd, buf, sizeof(input_data_hdr) + 4, 0);
}

int main(void)
{
    int rc = 0;
    int sd_main, sd_input, sd_display;
    uint64_t serial = 1;
    uint32_t session_id;
    char keycode_buf[4] = {0};
    bool ctrl_down = false;
    spice_conn_t spice_connection = {0};
    Display *display;
    Window root_window;
    XEvent event;

    sd_main = spice_connect();
    if (!spice_channel_main(sd_main, &session_id)) {
        fprintf(stderr, "failed to create main channel\n");
        return 1;
    }
    sd_display = spice_connect();
    if (!spice_channel_display(sd_display, session_id)) {
        fprintf(stderr, "failed to create display channel\n");
        return 1;
    }
    sd_input = spice_connect();
    if (!init_channel(sd_input, session_id, SPICE_CHANNEL_INPUTS, 0, 0)) {
        fprintf(stderr, "failed to create input channel\n");
        return 1;
    }

    display = XOpenDisplay(NULL);
    if (display == NULL) {
        fprintf(stderr, "Unable to open X display\n");
        rc = 1;
        goto out;
    }

    root_window = DefaultRootWindow(display);
    XGrabKeyboard(display, root_window, True, GrabModeAsync,
            GrabModeAsync, CurrentTime);

    for (;;) {
        XNextEvent(display, &event);

        if (event.type == KeyPress) {
            printf("Key pressed (keycode: %#x)\n", event.xkey.keycode);

            if (event.xkey.keycode == 0x40) {
                ctrl_down = true;
            } else if (event.xkey.keycode != 0x18 && ctrl_down) {
                ctrl_down = false;
            }

            if (ctrl_down && event.xkey.keycode == 0x18) {
                printf("quit...\n");
                break;
            }

            keycode_buf[0] = event.xkey.keycode - 0x08;
            send_key(sd_input, serial++,
                    (const unsigned char *) keycode_buf, false);
        } else if (event.type == KeyRelease) {
            printf("Key released (keycode: %#x)\n", event.xkey.keycode);

            keycode_buf[0] = event.xkey.keycode + 0x78;
            send_key(sd_input, serial++,
                    (const unsigned char *) keycode_buf, true);
        }
    }

    XUngrabKeyboard(display, CurrentTime);
    XCloseDisplay(display);
out:
    close(sd_input);
    close(sd_display);
    close(sd_main);

    return rc;
}
