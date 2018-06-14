/* -------------------------------------------------------------------------
 *
 * This file is part of the TIP project code base.
 * Copyright (C) Ericsson Danmark A/S 2005-2007
 *
 * ------------------------------------------------------------------------- */
/** 
 *  @file
 *  @version $Revision$
 *  @date    $Date$
 *
 *  @brief
 *  L2TP main API implementation.
 *
 * This file implements the L2TP zone and endpoint part of the L2TP library.
 * It also implements the main receive packet and the first decoding of
 * messages. Session payload packets are forwarded to the session module and
 * control messages are forwarded to the tunnel RTX module that is responsible
 * for L2TP header validation, reordering and acknowledge of packets. Packets 
 * accepted are forwarded to the tunnel module when in order.
 */

/*
 * ======================
 * ===    Includes    ===
 * ======================
 */

#include "mem.h"
#include "packet.h"
#include "align.h"
#include "dbg.h"
#include "tip_string.h"
#include "tip_globals.h"
#if L2TP_CFG_REDUNDANCY
#include "tims.h"
#endif

#include "l2tp_api.h"
#include "l2tp.h"
#include "l2tp_zone.h"
#include "l2tp_util.h"
#include "l2tp_tpl.h"
#include "l2tp_avp.h"
#include "l2tp_tunnel.h"
#include "l2tp_tunnel_rtx.h"
#include "l2tp_session.h"
#if L2TP_CFG_DIGEST_MD5
#include "l2tp_digest.h"
#endif
#include "l2tp_tpl_api.h"

/**
 * @ingroup L2TPint
 */

/*
 * ===================
 * ===    Debug    ===
 * ===================
 */
DBG_DEBUG_MODULE_DECLARE(l2tp_api)
#define DBG_DEBUG_MODULE l2tp_api
 
/*
 * ===================================
 * ===    Local Macro Constants    ===
 * ===================================
 */
/**
 * @ingroup L2TPint
 * Default idle timer before sending Hello message for keepalive.
 */
#define L2TP_CFG_HELLO_TIMEOUT 60000 /* milliseconds */

#if !L2TP_CONTROL_PATH 
#undef L2TP_ADDR_TO_STR
#define L2TP_ADDR_TO_STR(_addr_) "NoAddr"
#endif

/*
 * ===================================
 * ===    Local Function Macros    ===
 * ===================================
 */

/*
 * ================================
 * ===    Local Enumerations    ===
 * ================================
 */

/*
 * ============================
 * ===    Local Typedefs    ===
 * ============================
 */

/*
 * ===========================
 * ===    Local Structs    ===
 * ===========================
 */

/*
 * ============================
 * ===    Opaque Structs    ===
 * ============================
 */

/*
 * ==============================
 * ===    Global Variables    ===
 * ==============================
 */

TIP_GLOBALS_DECLARE(MODULE_L2TP, l2tp_global_variables_t);

/*@-exportheadervar@*/
const l2tp_global_variables_t l2tp_globals_init_values = {
    0,     /* l2tp_avp_validate_result*/
    0,     /* l2tp_avp_validate_error*/
    NULL,  /* *l2tp_avp_validate_text*/
    NULL,  /* *l2tp_avp_elem_pool*/
    NULL,  /* *l2tp_avp_list_pool*/
    0,     /* serial_number*/
    0,     /* mini_cookie*/
    {      /* l2tp_addr_str[2][60]*/
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
        ,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    },
    0      /* l2tp_addr_str_idx*/    
};
/*@=exportheadervar@*/

/*
 * =============================
 * ===    Local Variables    ===
 * =============================
 */

/*
 * ============================================
 * ===    Prototypes for Local Functions    ===
 * ============================================
 */

#if L2TP_CONTROL_PATH
/**
 * @ingroup L2TPint
 * @param zone        Pointer to L2TP zone.
 * @param local_addr  Pointer to local TPL address.
 * @param peer_addr   Pointer to peer TPL address.
 * @return  Pointer to matching endpoint or NULL if no matching endpoints.
 * @brief
 * Find endpoint matching TPL addresses.
 *
 * Search for matching endpoint in the specified @a zone. Endpoints may have
 * an unspecified peer address, which means that any peer address will match.
 */
/*@null@*/
static l2tp_endpoint_t* l2tp_endpoint_find(l2tp_zone_t *zone, 
                                           l2tp_tpl_addr_t *local_addr, 
                                           l2tp_tpl_addr_t *peer_addr);

/**
 * @ingroup L2TPint
 * @param endpoint    Pointer to L2TP endpoint.
 * @param peer_addr   Pointer to peer TPL address.
 * @param peer_id     Peer control connection ID.
 * @return  Pointer to found tunnel or NULL if not found.
 * @brief
 * Check if there already exists a tunnel to same peer connection 
 * (same IP address and Assigned Control Connection Id).
 */
/*@null@*/
static l2tp_tunnel_t *l2tp_endpoint_find_tunnel(l2tp_endpoint_t *endpoint, 
                                l2tp_tpl_addr_t *peer_addr, uint32_t peer_id);

#if L2TP_CFG_REDUNDANCY
/**
 * @ingroup L2TPint
 * @param timer    Timer id
 * @return  Nothing
 * @brief
 * Tunnel old ID's table timeout callback function. Clears all entries
 * in the tunnel ID mapping allowing the local ID's to be used for
 * new tunnels.
 */
static void l2tp_tunnel_old_ids_timeout_cb(tims_id_t timer);
#endif

#endif /* L2TP_CONTROL_PATH */

/*
 * ===========================
 * ===    Main Function    ===
 * ===========================
 */

/*
 * ============================================
 * ===    Local Function Implementations    ===
 * ============================================
 */


/*
 * ===============================================
 * ===    Exported Function Implementations    ===
 * ===============================================
 */
bool l2tp_tip_init(void)
{
#if L2TP_CONTROL_PATH
#if L2TP_TPL_USE_TIPSTACK && 0
    osi_pc_init(); /* Only once per process. Socket is doing this */
#endif
    TIP_GLOBALS_INIT(MODULE_L2TP, &l2tp_globals_init_values,
                     l2tp_global_variables_t);
#endif

    /*@-globstate@*/ 
    return l2tp_tpl_tip_init();
    /*@=globstate@*/ 
}


l2tp_zone_t *l2tp_zone_create(l2tp_tunnel_event_cb_t tunnel_cb,
                              l2tp_session_event_cb_t session_cb,
                              l2tp_session_data_cb_t session_data_cb)
{
    uint32_t i;
    l2tp_zone_t *zone;

#if !L2TP_CONTROL_PATH
    TIP_PARAM_NOT_USED(tunnel_cb);
    TIP_PARAM_NOT_USED(session_cb);
#endif
#if !L2TP_DATA_PATH
    DBG_ASSERT(tunnel_cb!=NULL);
    DBG_ASSERT(session_cb!=NULL);
#endif
    DBG_ASSERT(session_data_cb!=COMMON_NULL);

    zone = mem_alloc(sizeof(*zone));
    if (zone == NULL) {
        DBG_TRACE(dbg_lvl_no_resources, ("L2TP zone alloc, no resources"));
        return NULL;
    }
#if L2TP_CONTROL_PATH
    if (!l2tp_avp_init()) {
        DBG_TRACE(dbg_lvl_no_resources, ("L2TP AVP Init, no resources"));
        mem_free(zone);
        return NULL;
    }
    zone->tunnel_event_cb = tunnel_cb;
    zone->session_event_cb = session_cb;
    zone->redir_addr_cb = NULL;
#endif

    zone->session_data_cb = session_data_cb;
    zone->endpoint_list = NULL;
    zone->session_last_used_id = 0;
#if L2TP_ID_LOOKUP
    zone->next_connection_id = 0;
    for (i=0; i <= L2TP_ID_HASH_TABLE_SIZE; i++)
        zone->Session_ID_hash_table[i] = 0;
#endif
    for (i=0;i<L2TP_TUNNEL_TABLE_SIZE;i++)
        zone->tunnel_list[i] = NULL;

    for (i=0;i<L2TP_CFG_MAX_SESSIONS;i++)
        zone->session_list[i] = NULL;

#if L2TP_CFG_USE_MINI_COOKIE
    {
        uint32_t cookie;
        srand(tip_get_timestamp());
        cookie = (uint32_t) rand() & ((1<<L2TP_CFG_TUNNEL_COOKIE_BIT_SIZE)-1);
        for (i=0; i<L2TP_TUNNEL_TABLE_SIZE;i++)
            zone->tunnel_cookie[i]  = cookie;
        cookie = (uint32_t) rand() & ((1<<L2TP_CFG_SESSION_COOKIE_BIT_SIZE)-1);
        for (i=0;i<L2TP_CFG_MAX_SESSIONS;i++)
            zone->session_cookie[i] = cookie;
    }
#endif

#if L2TP_CONTROL_PATH
#if L2TP_CFG_REDUNDANCY
    zone->tunnel_old_ids = NULL;
    zone->old_ids_timer = TIMS_UNDEF;
    zone->old_ids_timer_running = false;
#endif

    zone->params[l2tp_param_rto_init] = 1000;
    zone->params[l2tp_param_rto_max] = 8000;
    zone->params[l2tp_param_rtx_max] = 10;
    zone->params[l2tp_param_rtx_sccrq_max] = 10;
    zone->params[l2tp_param_hello_interval] = L2TP_CFG_HELLO_TIMEOUT;
    zone->vrid = L2TP_TPL_DEFAULT_VRID;
#endif

    DBG_TRACE(dbg_lvl_info, ("L2TP zone %p created", (void*)zone));
    return zone;
}

void  l2tp_zone_destroy(l2tp_zone_t *zone)
{
    l2tp_endpoint_t *endpoint;

    DBG_TRACE(dbg_lvl_info, ("L2TP zone %p destroyed", (void*)zone));
#if L2TP_CONTROL_PATH
    l2tp_avp_uninit();
#if L2TP_CFG_REDUNDANCY
    if (zone->old_ids_timer != TIMS_UNDEF) {
        tims_free(zone->old_ids_timer);
    }
    if (zone->tunnel_old_ids != NULL) {
        mem_free(zone->tunnel_old_ids);
    }
#endif
#endif
    endpoint = zone->endpoint_list;
    while (endpoint != NULL) {
        l2tp_endpoint_t *next_endpoint;
        next_endpoint = endpoint->next;
        l2tp_endpoint_destroy(endpoint);
        endpoint = next_endpoint;
    }
    mem_free(zone);
}


void l2tp_set_param(l2tp_zone_t *zone, l2tp_param_t param, uint32_t value)
{
    DBG_ASSERT(param<l2tp_param_no_of);
    DBG_TRACE(dbg_lvl_user_3, ("Set param %"PRIu8"=%"PRIu32, param, value));

    if (value > 0xffff &&
        (param == l2tp_param_rto_init ||
         param == l2tp_param_rto_max ||
         param == l2tp_param_rtx_max ||
         param == l2tp_param_rtx_sccrq_max)) {
        DBG_TRACE(dbg_lvl_uncommon, 
                ("parameter %"PRIu8" only 16 bit value", param));
        DBG_NOT_REACHED();
        value = value & 0xffff;
    }
    zone->params[param] = value;
}

uint32_t l2tp_get_param(l2tp_zone_t *zone, l2tp_param_t param)
{
    DBG_ASSERT(param<l2tp_param_no_of);

    return zone->params[param];
}

#if L2TP_TPL_USE_VRID
void l2tp_set_vrid(l2tp_zone_t *zone, uint32_t vrid)
{
    DBG_TRACE(dbg_lvl_user_3, ("Set VRID to %"PRIu32, vrid));
    zone->vrid = vrid;
}
#endif

l2tp_endpoint_t *l2tp_endpoint_create(l2tp_zone_t *zone,
                                      l2tp_tpl_addr_t *addr)
{
    l2tp_endpoint_t *endpoint;
    endpoint = mem_alloc(sizeof(*endpoint));
    if (endpoint == NULL) {
        DBG_TRACE(dbg_lvl_no_resources, 
            ("L2TP Endpoint %s Create, no resources", L2TP_ADDR_TO_STR(addr)));
        return NULL;
    }
    endpoint->next = zone->endpoint_list;
    zone->endpoint_list = endpoint;
    endpoint->bound = false;
    endpoint->zone = zone;
    l2tp_tpl_addr_cpy(&endpoint->addr, addr);

    DBG_TRACE(dbg_lvl_info, 
            ("Endpoint %s Created", L2TP_ADDR_TO_STR(addr)));

    return endpoint;
}

void  l2tp_endpoint_destroy(l2tp_endpoint_t *endpoint)
{
    l2tp_endpoint_t *ep;
    l2tp_tunnel_t *tunnel;
    uint32_t i;
    DBG_ASSERT(endpoint!=NULL);
    DBG_TRACE(dbg_lvl_info, 
            ("Endpoint %s Destroy", L2TP_ADDR_TO_STR(&endpoint->addr)));

    for (i=0;i<L2TP_TUNNEL_TABLE_SIZE;i++) {
        tunnel = endpoint->zone->tunnel_list[i];
        if (tunnel != NULL && tunnel->endpoint == endpoint) {
            l2tp_tunnel_destroy(tunnel);
        }
    }

    if (endpoint->bound) 
        l2tp_tpl_disconnect(endpoint->tpl_conn_id);

    ep = endpoint->zone->endpoint_list;
    if (ep == endpoint) {
        DBG_ASSERT(ep!=NULL); /* Lint */
        endpoint->zone->endpoint_list = ep->next;
    } else while (ep != NULL) {
        if (ep->next == endpoint) {
            ep->next = endpoint->next;
            break;
        }
        ep = ep->next;
    }
    DBG_ASSERT(ep!=NULL); /* Endpoint MUST be found in list! */
    mem_free(endpoint);
}


l2tp_res_t  l2tp_endpoint_listen(l2tp_endpoint_t *endpoint)
{
    l2tp_tpl_res_t tpl_res;
    l2tp_tpl_conn_id_t conn_id;
    DBG_TRACE(dbg_lvl_user_1, 
            ("Endpoint %s Listen", L2TP_ADDR_TO_STR(&endpoint->addr)));

    tpl_res = l2tp_tpl_listen(&endpoint->addr, endpoint->zone->vrid, &conn_id);

    switch (tpl_res) {
    case l2tp_tpl_res_ok:
        break;
    case l2tp_tpl_res_no_resources:
        return l2tp_res_no_resources;
    case l2tp_tpl_res_ill_state:
    case l2tp_tpl_res_in_use:
        return l2tp_res_ill_state;
    }
    endpoint->tpl_conn_id = conn_id;
    endpoint->bound = true;
    DBG_TRACE(dbg_lvl_info, ("L2TP endpoint bound"));
    return l2tp_res_ok;
}


void l2tp_recv_message(l2tp_zone_t *zone,
                        packet_t *pck
#if BTS_SOFT_SYNC_TIMESTAMP
                       , uint32_t timestamp
#endif
                        )
{
    l2tp_session_id_t session_id;
    uint8_t *buf;
    uint16_t size;
    annotation_l2tp_offset_t *tpl_offset;
#if L2TP_ID_LOOKUP
    uint32_t session_x;
    l2tp_session_t *lookup_session= NULL;
#endif

#if L2TP_CONTROL_PATH
    l2tp_tunnel_t *tunnel;
    l2tp_endpoint_t *endpoint;
    uint32_t ctrl_conn_id;
    uint32_t ctrl_conn_idx;
    uint32_t remote_id;
    uint16_t nr;
    uint16_t ns;
    uint16_t message_type;
    uint32_t peer_id;
    l2tp_avp_list_t *avp_list = NULL;
    l2tp_avp_t *avp;
    l2tp_tpl_addr_t local_addr;
    l2tp_tpl_addr_t peer_addr;
    uint8_t tos = 0;
#if L2TP_CFG_DIGEST_MD5
    l2tp_avp_t *digest_avp;
#endif
#endif

    DBG_TRACE(dbg_lvl_user_3, ("L2TP Recv Message"));
    DBG_ASSERT(packet_get_size(pck) < 0xffff);
    size = (uint16_t)packet_get_size(pck);
    /* Get L2TP message offset */
    tpl_offset = packet_annotation_get(pck, l2tp_offset);
    if(tpl_offset == NULL) {
        DBG_TRACE(dbg_lvl_uncommon, ("Missing Offset annotaion from TPL"));
        goto packet_dropped;
    }
    /* Test if Session Payload and session id valid */
    if(size < tpl_offset->offset + 4) {
        DBG_TRACE(dbg_lvl_protocol_error, ("L2TP size error %"PRIu16, size));
        goto packet_dropped;
    }
    buf = packet_access_linear(pck, tpl_offset->offset, 4, align_1, packet_access_ro);
    session_id.id = READ_ID(buf, 0, align_1);
    if (session_id.id != 0) {

#if L2TP_ID_LOOKUP
    session_x = SESSION_ID_HASH(session_id.id);
    if (zone->Session_ID_hash_table[session_x] == 0) {
        DBG_TRACE(dbg_lvl_user_1, ("Session_id.id: %" PRIu32 " not found in hash_table", session_id.id));
        session_id.id = 0;
    } else {
        lookup_session = zone->session_list[zone->Session_ID_hash_table[session_x]];
        DBG_ASSERT(lookup_session != NULL); /* lint */
        if (session_id.id == lookup_session->extern_local_id) {
            session_id.id = lookup_session->local_id.id;
            DBG_TRACE(dbg_lvl_user_3, ("External_id: %" PRIu32 " matched to local_id: %" PRIu32, lookup_session->extern_local_id, session_id.id));
        } else if (lookup_session->next_session_list_index == 0) {
            DBG_TRACE(dbg_lvl_user_1, ("Session_id.id: %" PRIu32 " not found in lookup table", session_id.id));
            session_id.id = 0;                              /* No next session to lookup*/
        }
        else {
            uint32_t i;
            session_x = lookup_session->next_session_list_index;
            for (i = 0; i < L2TP_CFG_MAX_SESSIONS; i++ ) {
                lookup_session = zone->session_list[session_x];
                if (session_id.id == lookup_session->extern_local_id) {
                    session_id.id =lookup_session->local_id.id;  /* Sess external and local match found.*/
                    DBG_TRACE(dbg_lvl_user_3, ("External_id: %"PRIu32" matched to local_id: %"PRIu32, lookup_session->extern_local_id, session_id.id));
                    break;
                }
                if (lookup_session->next_session_list_index == 0) {
                    DBG_TRACE(dbg_lvl_user_1, ("Session_id.id: %" PRIu32 " not found in session_list (1)", session_id.id));
                    session_id.id = 0;        /* Session ID have not been used before */
                    break;
                }
                session_x = lookup_session->next_session_list_index;
            }
            if (i >= L2TP_CFG_MAX_SESSIONS ) {
                DBG_TRACE(dbg_lvl_user_1, ("Session_id.id: %" PRIu32 " not found in session_list (2)", session_id.id));
                session_id.id = 0;
            }
        }
    }
#endif

#if L2TP_CONTROL_PATH && L2TP_CFG_SESSION_IP_CHECK && !L2TP_TPL_USE_GRAT
    {
    /* Check msg peer IP is equal to tunnels destination IP */
        l2tp_session_t *session; 
        uint32_t idx;
        /* Get TPL addresses */
        if (!l2tp_tpl_get_pck_addrs(pck, &peer_addr, &local_addr)) {
            DBG_TRACE(dbg_lvl_packet_no_resources, ("Get TPL address failed"));
           goto packet_dropped;
        }
        idx = SESSION_INDEX(session_id.id);

        DBG_TRACE(dbg_lvl_user_4,
                  ("S:%"PRIu32" Recv: Session Payload, Peer addr=%s",
                   idx, L2TP_ADDR_TO_STR(&peer_addr)));

        if (idx >= L2TP_CFG_MAX_SESSIONS) {
            DBG_TRACE(dbg_lvl_packet_dropped, ("Session index too big %"PRIu32, idx));
            goto packet_dropped;
        }

        session = zone->session_list[idx];
        
        if ((session != NULL) && (!l2tp_tpl_addr_equal(&peer_addr, &session->tunnel->dst_addr)))
        {
            DBG_TRACE(dbg_lvl_packet_dropped,
                ("Invalid peer_addr: %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
                peer_addr.addr[0], peer_addr.addr[1],
                peer_addr.addr[2], peer_addr.addr[3]));
            goto packet_dropped;
        }
    }
#endif
    
#if !L2TP_CFG_NO_IPHDR
        packet_prefix_remove(pck, tpl_offset->offset);
#endif
        /* Forward Payload to Session */
        l2tp_session_event(zone, 
                           &session_id,
                           pck
#if BTS_SOFT_SYNC_TIMESTAMP
                           , timestamp
#endif
                           );
        return;
    }

#if L2TP_CONTROL_PATH
#if L2TP_CFG_NO_IPHDR
    local_addr.protocol = l2tp_tpl_addr_type_inet;
    local_addr.lgt = 0;
    peer_addr.protocol = l2tp_tpl_addr_type_inet;
    peer_addr.lgt = 0;
#else
  /* get tos from incoming packet - might be set for tunnel data if
     * message is a sccrq
     */
    if (!l2tp_tpl_get_pck_tos(pck, &tos)) {
        DBG_TRACE(dbg_lvl_packet_no_resources, ("Get Tos failed"));
        goto packet_dropped;
    }

    /* Get TPL addresses */
    if (!l2tp_tpl_get_pck_addrs(pck, &peer_addr, &local_addr)) {
        DBG_TRACE(dbg_lvl_packet_no_resources, ("Get TPL address failed"));
        goto packet_dropped;
    }
#endif
    /* Remove TPL header */
    packet_prefix_remove(pck, tpl_offset->offset + (uint16_t)l2tp_msg_offs_ctrl_ip);
    size = (uint16_t)packet_get_size(pck);
    if(size < (uint16_t)(l2tp_msg_offs_avp + 8 /* Message Type size */)) {
        DBG_TRACE(dbg_lvl_protocol_error, ("L2TP size error %"PRIu16, size));
        goto packet_dropped;
    }
    buf = packet_access_linear(pck, 0, size, align_1, packet_access_ro);
    if(buf == NULL) {
        DBG_TRACE(dbg_lvl_packet_no_resources, ("Packet access no resources"));
        goto packet_dropped;
    }
    ctrl_conn_id = READ_ID(buf, l2tp_msg_offs_ctrl_conid, align_1);
    if((READ16B(buf, l2tp_msg_offs_length, align_1) != size)) {
        DBG_TRACE(dbg_lvl_protocol_error, ("L2TP LENGTH error"));
        goto packet_dropped;
    }
    ns = READ16B(buf, l2tp_msg_offs_ns, align_4);
    nr = READ16B(buf, l2tp_msg_offs_nr, align_4);
    DBG_TRACE(dbg_lvl_user_4, ("CTRL_ID=%"PRIu32", NS=%"PRIu16", NR=%"PRIu16, ctrl_conn_id, ns, nr));
    avp_list = l2tp_avp_decode(buf + l2tp_msg_offs_avp, (uint16_t)(size - l2tp_msg_offs_avp));
    if(avp_list == NULL) {
        DBG_TRACE(dbg_lvl_packet_no_resources, ("AVP decode, no resources"));
        goto packet_dropped;
    }
    /* Get Message Type */
    avp = l2tp_avp_get_first(avp_list);
    if(avp != NULL && l2tp_avp_vendor_id(avp) == 0 && l2tp_avp_type(avp) == l2tp_avp_message_type &&
       l2tp_avp_validate(avp, l2tp_msg_unknown, false)) {
        message_type = l2tp_avp_value_16b(avp);
    } else {
        message_type = l2tp_msg_unknown;
    }
    DBG_TRACE(dbg_lvl_user_3, ("L2TP Recv Message %"PRIu16" [%s]", message_type, l2tp_msg_type_to_str(0,message_type)));
    if((buf[l2tp_msg_offs_ver] & 0xf) != 3) {
        DBG_TRACE(dbg_lvl_packet_dropped, ("L2TP version %"PRIu8" not supported", (buf[l2tp_msg_offs_ver] & 0xf)));
        if(message_type == l2tp_msg_ack) {
            goto packet_dropped;
        }
        avp = l2tp_avp_find(avp_list, 0, l2tp_avp_assign_con_id);
        if(avp == NULL) {
            goto packet_dropped;
        }
        peer_id = l2tp_avp_value_32(avp);        
        l2tp_send_message_without_tunnel(l2tp_msg_stopccn, &local_addr, &peer_addr,  peer_id, 0,l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                                         l2tp_res_code_protocol_version, L2TP_ERROR_CODE_UNDEF, NULL);
        goto packet_dropped;
    }
    if((buf[l2tp_msg_offs_tls] & (L2TP_CTRL_T_BIT | L2TP_CTRL_L_BIT | L2TP_CTRL_S_BIT)) != 
       (L2TP_CTRL_T_BIT | L2TP_CTRL_L_BIT | L2TP_CTRL_S_BIT)) {
        DBG_TRACE(dbg_lvl_protocol_error, ("TLS bits not set"));
        goto packet_dropped;
    }
    /* If message digest, do integrity check */
#if L2TP_CFG_DIGEST_MD5
    if((avp = l2tp_avp_find(avp_list, 0, l2tp_avp_message_digest)) != NULL) {
        /* digest avp exist */
#define DIGEST_KEY_SIZE (16)

        uint16_t head_lgt = l2tp_msg_offs_avp;
        /* precalculated key, from zero length secret and the octet 2 */
        uint8_t key[DIGEST_KEY_SIZE] = {0x7b, 0x60, 0x85, 0xfb, 0xf4, 0x59, 0x33, 0x67,
                           0x0a, 0xbc, 0xb0, 0x7a, 0x27, 0xfc, 0xea, 0x5e};
        uint8_t digest_org[DIGEST_KEY_SIZE];
        uint8_t digest[DIGEST_KEY_SIZE];
        uint16_t digest_avp_offs = head_lgt + (uint16_t)8 /* Message Type AVP*/;
        uint32_t digest_offs = (uint32_t)(l2tp_avp_offs_attr_value + 1 /* Digest Type */);

        digest_avp = l2tp_avp_get_next(avp_list);
        if((digest_avp == NULL) || (l2tp_avp_type(digest_avp) != l2tp_avp_message_digest)) {
            DBG_TRACE(dbg_lvl_packet_no_resources, ("Message Digest not second AVP"));
            goto packet_dropped;
        }
        buf = packet_access_linear(pck, digest_avp_offs, digest_offs + DIGEST_KEY_SIZE, align_1, packet_access_rw);
        if(buf == NULL) {
            DBG_TRACE(dbg_lvl_packet_no_resources, ("Packet access failed"));
            goto packet_dropped;
        }
        tip_memcpy(digest_org, buf + digest_offs, DIGEST_KEY_SIZE);
        /* Zero Message Digest */
        tip_memset(buf + digest_offs, 0, DIGEST_KEY_SIZE);
        if(!l2tp_digest_hmac_md5(0 /* ignore before */, 0 /* ignore after */,
                                 pck, key /* key */,  DIGEST_KEY_SIZE /* key length*/,
                                 digest /* digest */, DIGEST_KEY_SIZE /* digest length */)) {
            DBG_TRACE(dbg_lvl_packet_no_resources, ("Send packet, no digest resources"));
            goto packet_dropped;
        }
        if(tip_memcmp(digest_org, digest, DIGEST_KEY_SIZE) != 0) {
            if (peer_addr.protocol==l2tp_tpl_addr_type_inet) {
                DBG_TRACE(dbg_lvl_packet_dropped,
                    ("MD error: peer IP %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8
                     ", Msg %"PRIu16", CtrlId %"PRIu32,
                     peer_addr.addr[0], peer_addr.addr[1],
                     peer_addr.addr[2], peer_addr.addr[3],
                     message_type, ctrl_conn_id)); /* Unreliable! Digest error */
            } else {
                DBG_TRACE(dbg_lvl_packet_dropped, ("Message Digest Error"));
            }
            goto packet_dropped;
        }
    } 
    else {
#if L2TP_CFG_DIGEST_MD5_ACCEPT_MISSING
        DBG_TRACE(dbg_lvl_user_4, ("Message Digest not found, accepted when testing"));
#else
        DBG_TRACE(dbg_lvl_packet_dropped, ("Message Digest not found"));
        goto packet_dropped;
#endif
    }
#endif

#if L2TP_ID_LOOKUP
    ctrl_conn_idx = 0;
    if (ctrl_conn_id != 0){
        uint32_t i;
        buf = packet_access_linear(pck, 0, size, align_1, packet_access_ro);
        for (i = 1; i < L2TP_TUNNEL_TABLE_SIZE; i++) {
            if (zone->tunnel_list[i] != NULL){
                if (zone->tunnel_list[i]->extern_local_id == ctrl_conn_id) {
                    DBG_ASSERT(buf != NULL); /* lint */
                    DBG_TRACE(dbg_lvl_user_4, ("Tunnel external_local_id: %" PRIu32 " mapped to local_id: %" PRIu32, zone->tunnel_list[i]->extern_local_id, i));
                    ctrl_conn_idx = zone->tunnel_list[i]->local_id;
                    WRITE32(buf, l2tp_msg_offs_ctrl_conid, align_1, ctrl_conn_idx);
                    i = 0;
                    break;
                }
            }
        }
        if (i != 0) {
            DBG_TRACE(dbg_lvl_packet_dropped, ("Tunnel with ctrl_conn_id: %" PRIu32 " not found in tunnel_list.", ctrl_conn_id));
        }
    }
#else
    ctrl_conn_idx = ctrl_conn_id;
#endif
    /* Find/allocate Tunnel */
    if (message_type == l2tp_msg_sccrq) {
        /* ------------------- */
        /* ------ SCCRQ ------ */
        /* ------------------- */
        l2tp_tpl_res_t tpl_res;

        DBG_TRACE(dbg_lvl_info, ("Incoming Tunnel (%s,%s)", 
                L2TP_ADDR_TO_STR(&local_addr),
                L2TP_ADDR_TO_STR(&peer_addr)));

        avp = l2tp_avp_find(avp_list, 0, l2tp_avp_assign_con_id);
        if (avp==NULL) {
            /* We need a control connection id to send a StopCCN */
            DBG_TRACE(dbg_lvl_protocol_error, 
                    ("SCCRQ without assigned control ID"));
            goto packet_dropped;
        }
        peer_id = l2tp_avp_value_32(avp);
        DBG_TRACE(dbg_lvl_user_1, ("SCCRQ peer control id %"PRIu32, peer_id));

        if (ctrl_conn_id != 0 || ns != 0 || nr != 0) {
            DBG_TRACE(dbg_lvl_protocol_error, ("Illegal SCCRQ"));
            l2tp_send_message_without_tunnel(l2tp_msg_stopccn,
                &local_addr, &peer_addr, 
                 peer_id, 0, l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                 l2tp_res_code_error, l2tp_err_code_out_of_range,
                 "Erroneous field in L2TP control header");
            goto packet_dropped;
        }

        /* Find Endpoint from TPL addresses */
        endpoint = l2tp_endpoint_find(zone, &local_addr, &peer_addr);
        if (endpoint == NULL) {
            DBG_TRACE(dbg_lvl_packet_dropped,
                    ("Incoming Tunnel, Endpoint not found"));
            l2tp_send_message_without_tunnel(l2tp_msg_stopccn,
                &local_addr, &peer_addr, 
                 peer_id, 0, l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                 l2tp_res_code_error, l2tp_err_code_no_conn_exists,
                 "Unknown network layer address");
            goto packet_dropped;
        }

        /* Check if we are already connected to this peer with the same
           Ctrl Conn Id. If so, ignore this SCCRQ message, because it is
           probably just a retransmission of a previous SCCRQ and since we
           know about the peer_id, we are trying to send SCCRP. */
        tunnel = l2tp_endpoint_find_tunnel(endpoint, &peer_addr, peer_id);
        if (tunnel != NULL) {
            DBG_TRACE(dbg_lvl_user_1, 
                ("Recv SCCRQ with same control id as existing conn in %s",
                 l2tp_tunnel_state_to_str(tunnel->state)));
            switch (tunnel->state) {
            case l2tp_tunnel_st_wait_ctl_conn:
                /* Retransmitted SCCRQ, ignore */
                tunnel->recv_data_ok++;
                goto forward_packet;
            case l2tp_tunnel_st_established:
            case l2tp_tunnel_st_wait_ctl_reply:
                /* Peer is sending SCCRQ with same control connection id
                   as existing connection. We better close and destroy
                   our end and continue handling the new connection.
                 */
                tunnel->peer_id = 0; /* Do only local close */
                l2tp_tunnel_stop(tunnel, l2tp_res_code_error, 
                                 l2tp_err_code_no_general_error, 
                                 "SCCRQ received on connection");
                /* Since tunnel->peer_id == 0, the tunnel is destroyed now */
                tunnel = NULL;
                break;
            default:
                /* Peer is sending SCCRQ with same control connection id
                   as existing connection. We better destroy our end and
                   continue handling the new connection.
                 */
                DBG_ASSERT(tunnel!=NULL); /* Lint warning */
                l2tp_tunnel_destroy(tunnel);
                tunnel = NULL;
                break;
            }
        }

        /* Create Tunnel for incoming connection */
        tunnel = l2tp_tunnel_create(endpoint);
        if (tunnel == NULL) {
            DBG_TRACE(dbg_lvl_no_resources,
                    ("Incoming create tunnel, no resources"));
            l2tp_send_message_without_tunnel(l2tp_msg_stopccn,
                 &local_addr, &peer_addr, 
                 peer_id, 0, l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                 l2tp_res_code_error, l2tp_err_code_no_resources,
                 "No more Tunnel resources");
            goto packet_dropped;
        }
        tunnel->user_closed = true; /* Tunnel not known in user yet */
        tunnel->recv_data_ok++;

        tunnel->peer_id = peer_id;
        l2tp_tpl_addr_cpy(&tunnel->dst_addr, &peer_addr);
        /* assigning former determined tos - we now  proberly need it */
        tunnel->tos = tos;
        tpl_res = l2tp_tpl_connect(&endpoint->addr,
                                 &tunnel->dst_addr, zone->vrid,
                                 &tunnel->tpl_conn_id);
        if (tpl_res != l2tp_tpl_res_ok) {
            DBG_TRACE(dbg_lvl_packet_dropped, 
                    ("TPL connect failed with %"PRIu8, tpl_res));
            l2tp_send_message_without_tunnel(l2tp_msg_stopccn,
                 &local_addr, &peer_addr, 
                 peer_id, 0, l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                 l2tp_res_code_error, l2tp_err_code_no_resources,
                 "network layer connect problems");
            l2tp_tunnel_destroy(tunnel);
            goto packet_dropped;
        }
    } else {
        /* Other messages than SCCRQ */
#if L2TP_CFG_REDUNDANCY
        bool is_old_id = false;
#endif

        avp = l2tp_avp_find(avp_list, 0, l2tp_avp_assign_con_id);
        remote_id = (avp==NULL) ? 0 : l2tp_avp_value_32(avp);
        DBG_COND_TRACE(dbg_lvl_user_1, true, //avp!=NULL,
                       ("Remote id %" PRIu32 ", connection_id: %" PRIu32, remote_id, ctrl_conn_id));

        /* StopCCN with connection id 0 and Assigned Connection Id AVP */
        if (ctrl_conn_idx == 0 &&
            message_type == l2tp_msg_stopccn &&
            remote_id != 0) {
            uint32_t i;
            /* Do reverse lookup of con id from AVP */
            for (i = 1; i < L2TP_TUNNEL_TABLE_SIZE; i++) {
                tunnel = zone->tunnel_list[i];
                if (tunnel != NULL
                    && tunnel->peer_id == remote_id
#if !L2TP_CFG_NO_IPHDR
                    && l2tp_tpl_addr_equal(&peer_addr, &tunnel->dst_addr)
#endif
                   ) {
                    ctrl_conn_idx = tunnel->local_id; /* just set connection id and continue */
                    DBG_TRACE(dbg_lvl_info,
                        ("Reverse lookup matches id %"PRIu32, ctrl_conn_idx));
                    break;
                }
            }
        }

        tunnel = l2tp_tunnel_find(zone, ctrl_conn_idx);

        if (tunnel == NULL) {
#if L2TP_CFG_REDUNDANCY
            uint32_t idx = TUNNEL_INDEX(ctrl_conn_idx);
            /* Lookup conn id in old tunnels from failing board */
            if (ctrl_conn_idx < L2TP_TUNNEL_TABLE_SIZE &&
                zone->tunnel_old_ids != NULL &&
                zone->tunnel_old_ids[idx].remote_id != 0 &&
#if L2TP_CFG_USE_MINI_COOKIE
                zone->tunnel_old_ids[idx].local_id == ctrl_conn_id &&
#endif
                (remote_id == 0 ||
                 remote_id == zone->tunnel_old_ids[idx].remote_id)) {

                DBG_TRACE(dbg_lvl_info,
                    ("Recv msg %"PRIu16" on old tunnel %"PRIu32,
                     message_type, ctrl_conn_idx));
                is_old_id = true;
                remote_id = zone->tunnel_old_ids[idx].remote_id;
                if (message_type == l2tp_msg_ack) {
                    if (zone->tunnel_old_ids[idx].stopped) {
                        /* Waiting for Ack - got it */
                        DBG_TRACE(dbg_lvl_info,
                            ("Old tunnel id table, clear entry %"PRIu32,
                             ctrl_conn_idx));
                        zone->tunnel_old_ids[idx].remote_id = 0;
                        zone->tunnel_old_ids[idx].stopped = false;
                    }
                } else {
                    /* Send StopCCN and wait for ACK */
                    zone->tunnel_old_ids[idx].stopped = true;
                }
            } else
#endif
            if (peer_addr.protocol==l2tp_tpl_addr_type_inet) {
                DBG_TRACE(dbg_lvl_packet_dropped,
                    ("Unkn CtrlId: peer IP %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
                     ", Msg %" PRIu16 " [%s]",
                     peer_addr.addr[0], peer_addr.addr[1],
                     peer_addr.addr[2], peer_addr.addr[3],
                     message_type, l2tp_msg_type_to_str(0,message_type))); /* Unreliable! Digest error */
            } else {
                DBG_TRACE(dbg_lvl_packet_dropped,
                      ("Unknown Control Connection Id %"PRIu32, ctrl_conn_idx));
            }

            if (message_type == l2tp_msg_stopccn && remote_id != 0) {
                DBG_TRACE(dbg_lvl_info, ("Recv StopCCN, ACK it"));
                l2tp_send_message_without_tunnel(l2tp_msg_ack,
                     &local_addr, &peer_addr, 
                     remote_id, ctrl_conn_idx,
                     l2tp_tpl_addr_type_inet, zone->vrid, nr, ns+1,
                     0, 0, "");
                goto packet_dropped;
            }

            if (message_type == l2tp_msg_ack || 
                message_type == l2tp_msg_stopccn) {
                /* Do not send StopCCN on Ack and StopCCN to avoid loop! */
                goto packet_dropped;
            }

            if (remote_id==0 && ctrl_conn_id==0) {
                /* We need a control connection id to send a StopCCN */
                DBG_TRACE(dbg_lvl_packet_dropped,
                          ("Msg [%s] dropped, missing connection_id (remote_id=0, too)",
                           l2tp_msg_type_to_str(0, message_type)));
                goto packet_dropped;
            }

#if L2TP_CFG_REDUNDANCY
            /* Test for Redirect */
            if (is_old_id && zone->redir_addr_cb != NULL) {
                char redir_addr[] = "000.000.000.000";
                /* Get redirect IP address */
                if ((*zone->redir_addr_cb)(ctrl_conn_idx, remote_id,
                                           &peer_addr, redir_addr)) {
                    DBG_TRACE(dbg_lvl_info, ("Got Redir Addr %s",
                                redir_addr));
                    /* Send Redirect */
                    l2tp_send_message_without_tunnel(l2tp_msg_stopccn,
                         &local_addr, &peer_addr,
                         remote_id, ctrl_conn_idx,
                         l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                         l2tp_res_code_error,
                         l2tp_err_code_try_another_directed, redir_addr);
                    goto packet_dropped;
                }
            }
#endif

            l2tp_send_message_without_tunnel(l2tp_msg_stopccn,
                 &local_addr, &peer_addr, 
                 remote_id, ctrl_conn_idx,
                 l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                 l2tp_res_code_error, l2tp_err_code_no_conn_exists,
                 "Control connection does not exist.");
            goto packet_dropped;
        }

#if !L2TP_CFG_NO_IPHDR
        if (!l2tp_tpl_addr_equal(&peer_addr, &tunnel->dst_addr))
        {
            DBG_TRACE(dbg_lvl_packet_dropped,
                ("Invalid peer_addr: %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,
                peer_addr.addr[0], peer_addr.addr[1],
                peer_addr.addr[2], peer_addr.addr[3]));
            goto packet_dropped;
        }
#endif

        /* Check Assigned Control Connection Id in received SCCRP */
        if (message_type == l2tp_msg_sccrp) {
            /* ------------------- */
            /* ------ SCCRP ------ */
            /* ------------------- */

            avp = l2tp_avp_find(avp_list, 0, l2tp_avp_assign_con_id);
            peer_id = (avp != NULL) ? l2tp_avp_value_32(avp) : 0;

            if (peer_id == 0) {
                DBG_TRACE(dbg_lvl_protocol_error, 
                        ("SCCRP without Assigned Control Connection Id"));
                tunnel->recv_data_lost++;
                goto packet_dropped;
            }

            /* If we already have the peer ctrl conn id, check it with
               the one received in this message. This may happen, if peer
               creates 2 tunnels when SCCRQ is retransmitted, because of
               SCCRP loss. */
            if (tunnel->peer_id != 0 && tunnel->peer_id != peer_id) {
                l2tp_send_message_without_tunnel(l2tp_msg_stopccn,
                     &local_addr, &peer_addr, 
                     peer_id, 0, l2tp_tpl_addr_type_inet, zone->vrid, nr, ns,
                     l2tp_res_code_error, l2tp_err_code_no_conn_exists,
                     "Control connection does not exist.");
                tunnel->recv_data_lost++;
                goto packet_dropped;
            }
        } else if (message_type == l2tp_msg_stopccn) {
            /* ------------------- */
            /* ----- StopCCN ----- */
            /* ------------------- */
            /* Check Assigned Control Connection Id in received StopCCN */
 
            avp = l2tp_avp_find(avp_list, 0, l2tp_avp_assign_con_id);
            peer_id = (avp != NULL) ? l2tp_avp_value_32(avp) : 0;
 
            if (tunnel->peer_id != peer_id) {
                if (tunnel->peer_id != 0 && peer_id !=0 ) {
                    DBG_TRACE(dbg_lvl_protocol_error, 
                        ("StopCCN Ctrl Conn Id (%"PRIu32"~%"PRIu32
                         ") mismatch received", tunnel->peer_id, peer_id));
                    tunnel->recv_data_lost++;
                    goto packet_dropped;
                } else if (tunnel->peer_id == 0) {
                    tunnel->peer_id = peer_id; /* allows for Ack of StopCCN */
                }
            }
        }
        tunnel->recv_data_ok++;
    }

forward_packet:
    /* The handling of retransmitted SCCRQ jumps to this label. */

    l2tp_avp_list_destroy(&avp_list);
    avp_list = NULL;

    DBG_TRACE(dbg_lvl_user_2, ("Receive: #%"PRIu32" [%s], NS=%"
              PRIu16", NR=%"PRIu16", LGT=%"PRIu16,
              ctrl_conn_idx, 
              l2tp_msg_type_to_str(0,message_type), ns, nr, size));

    /* pass packet to Reliable Transmission level */
    l2tp_tunnel_rtx_recv_msg(tunnel, pck, message_type, ns, nr);

    return;

packet_dropped:
    l2tp_avp_list_destroy(&avp_list);
    packet_destroy(pck);
    return;

#else
    DBG_TRACE(dbg_lvl_packet_dropped, ("Non-datapath packet dropped"));
packet_dropped:
    packet_destroy(pck);
#endif
}

void l2tp_set_tunnel_ids(l2tp_zone_t *zone,
                         uint32_t local_id, uint32_t remote_id)
{
#if L2TP_CFG_REDUNDANCY
    uint32_t i;
    uint32_t idx = TUNNEL_INDEX(local_id);
    if (idx < L2TP_TUNNEL_TABLE_SIZE) {
        DBG_TRACE(dbg_lvl_info,
            ("Set old tunnel id mapping local_id=%"PRIu32",remote_id=%"PRIu32,
             local_id, remote_id));

        if (zone->tunnel_old_ids == NULL) {
            /* First set, allocate resources */
            zone->tunnel_old_ids = mem_alloc(
                        sizeof(l2tp_tunnel_old_ids_t)*L2TP_TUNNEL_TABLE_SIZE);
            zone->old_ids_timer = tims_alloc(TIMS_CONTINUOUS, 0);

            if (zone->tunnel_old_ids == NULL ||
                zone->old_ids_timer == TIMS_UNDEF) {
                DBG_TRACE(dbg_lvl_no_resources,
                          ("Tunnel ids allocate, no resources"));
                if (zone->tunnel_old_ids != NULL)
                    mem_free(zone->tunnel_old_ids);
                if (zone->old_ids_timer != TIMS_UNDEF)
                    tims_free(zone->old_ids_timer);
                return;
            }

            *(l2tp_zone_t**)(TIMS_USERID_PTR(zone->old_ids_timer)) = zone;
            zone->old_ids_timer_running = false;

            DBG_TRACE(dbg_lvl_info, ("Tunnel id table allocated"));
            for (i=0;i<L2TP_TUNNEL_TABLE_SIZE;i++) {
                zone->tunnel_old_ids[i].remote_id = 0;
                zone->tunnel_old_ids[i].stopped = false;
            }
        }

        if (!zone->old_ids_timer_running) {
            if (!tims_start(zone->old_ids_timer,
                            L2TP_CFG_REDUNDANCY_TIMEOUT*1000,
                            l2tp_tunnel_old_ids_timeout_cb)) {
                DBG_TRACE(dbg_lvl_warning, ("timer start failed, no tunnel id saved"));
                return;
            }
            zone->old_ids_timer_running = true;
        }
        zone->tunnel_old_ids[idx].remote_id = remote_id;
#if L2TP_CFG_USE_MINI_COOKIE
        zone->tunnel_old_ids[idx].local_id = local_id;
#endif
    } 
#else
    TIP_PARAM_NOT_USED(zone);
    TIP_PARAM_NOT_USED(local_id);
    TIP_PARAM_NOT_USED(remote_id);
#endif
}

void l2tp_set_redirect_addr_callback(l2tp_zone_t *zone, l2tp_redir_addr_cb_t cb)
{
    DBG_ASSERT(zone!=NULL);
    zone->redir_addr_cb = cb;
}

void l2tp_set_next_connection_id( l2tp_zone_t *zone,uint32_t next_connection_id)
{
#if L2TP_ID_LOOKUP
    zone->next_connection_id = next_connection_id;
#else
    TIP_PARAM_NOT_USED(zone);
    TIP_PARAM_NOT_USED(next_connection_id);
#endif
}

/*
 * ==================================
 * ===      Static functions      ===
 * ==================================
 */
#if L2TP_CONTROL_PATH
static l2tp_tunnel_t *l2tp_endpoint_find_tunnel(l2tp_endpoint_t *endpoint, 
                                l2tp_tpl_addr_t *peer_addr, uint32_t peer_id)
{
    l2tp_tunnel_t *tunnel;
    uint32_t i;

    for (i=0;i<L2TP_TUNNEL_TABLE_SIZE;i++) {
        tunnel = endpoint->zone->tunnel_list[i];
        if (tunnel != NULL && tunnel->endpoint == endpoint) {
            if (tunnel->peer_id == peer_id &&
                l2tp_tpl_addr_equal(&tunnel->dst_addr, peer_addr)) {
                return tunnel;
            }
        }
    }
    return NULL;
}

static l2tp_endpoint_t* l2tp_endpoint_find(l2tp_zone_t *zone, 
                                           l2tp_tpl_addr_t *local_addr, 
                                           l2tp_tpl_addr_t *peer_addr)
{
    l2tp_endpoint_t *endpoint;
    TIP_PARAM_NOT_USED(peer_addr);
    endpoint = zone->endpoint_list;
    while (endpoint != NULL) {
        DBG_TRACE(dbg_lvl_user_4, ("Compare %s with received %s", 
            L2TP_ADDR_TO_STR(&endpoint->addr), L2TP_ADDR_TO_STR(local_addr)));
#if L2TP_CFG_NO_IPHDR
        return endpoint;
#endif
        if (l2tp_tpl_addr_equal(local_addr, &endpoint->addr)) {
            return endpoint;
        }
        endpoint = endpoint->next;
    }
    return NULL;
}

#if L2TP_CFG_REDUNDANCY
static void l2tp_tunnel_old_ids_timeout_cb(tims_id_t timer)
{
    l2tp_zone_t *zone;
    DBG_TRACE(dbg_lvl_info, ("Old tunnel ids timeout, table cleared"));
    zone = *(l2tp_zone_t**)(TIMS_USERID_PTR(timer));
    if (zone->tunnel_old_ids != NULL) {
#if DBG_TRACES
        uint32_t i;
        uint32_t not_acked = 0;
        uint32_t not_stopped = 0;
        for (i=0;i<L2TP_TUNNEL_TABLE_SIZE;i++) {
            if (zone->tunnel_old_ids[i].remote_id != 0) {
                if (zone->tunnel_old_ids[i].stopped)
                    not_acked++;
                else
                    not_stopped++;
            }
        }
        DBG_COND_TRACE(dbg_lvl_warning, not_acked>0,
                       ("Tunnels not acked %"PRIu32, not_acked));
        DBG_COND_TRACE(dbg_lvl_warning, not_stopped>0,
                        ("Tunnels not stopped %"PRIu32, not_stopped));
#endif
        mem_free(zone->tunnel_old_ids);
        tims_free(zone->old_ids_timer);

        zone->tunnel_old_ids = NULL;
        zone->old_ids_timer = TIMS_UNDEF;
        zone->old_ids_timer_running = false;
    }
}
#endif

#endif /* L2TP_CONTROL_PATH */