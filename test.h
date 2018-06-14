

typedef unsigned char pco_ref_t;
typedef unsigned char uint8_t;
typedef signed short int16_t; 
typedef unsigned short uint16_t; 

typedef unsigned int uint32_t;
typedef uint32_t ref_t;

typedef struct ch_item
{
  uint8_t          activated;
  uint8_t          burst_counter;
}
ch_item_t;
typedef struct tn_item
{
  uint8_t          tn_enabled;
  uint8_t          ch_comb;    /* cc (i), (i)/(ii) ICM FR & (i)/(ii) ICM HR */
  uint8_t          no_of_freq;
  uint16_t         arfcn[64];
  uint8_t          rx_div;
  uint8_t          fas_in_progress;
  uint8_t          fas_suspended;
  uint8_t          fas_sub_ch;
  uint8_t          pdch_active;
  pco_ref_t       fas_chan;
  uint8_t          trans_id;
  int16_t         alt_index;  /* Index for alternative frequency */
  ch_item_t       chan[3];    /* FR, HR0 & HR1 */
}
tn_item_t;

typedef struct tn_item tn_item_fwd;


// The obj used, is found in tfs_stddef.h
/*--------------------- Channel Combination Enumeration ---------------------*/
#define MAX_SIZE_OF_SECTOR_KEY 256


typedef enum 
{
  CHAN_COMB_I,
  CHAN_COMB_II,
  CHAN_COMB_I_II,
  CHAN_COMB_I_II_VAMOS,
  CHAN_COMB_PDCH,
  CHAN_COMB_IV,
  CHAN_COMB_V,
  CHAN_COMB_V_CBCH,  
  CHAN_COMB_VI,
  CHAN_COMB_VII,
  CHAN_COMB_VII_CBCH,
  CHAN_COMB_VIII,
  CHAN_COMB_IX,
  CHAN_COMB_X,
  CHAN_COMB_EC,
  CHAN_COMB_NB
} 
chan_comb_enum;
typedef struct world
{
  int                    trx_instance;
  char                   sector[MAX_SIZE_OF_SECTOR_KEY];

  chan_comb_enum         curr_ch_comb [8][2];//tn,vsc
  ref_t                  ref;//Reference handler
//  fas_t                  fas;
  tn_item_fwd            *tn_table;

} world;

class gen_ref_handler
{
  public :
    gen_ref_handler (uint8_t dummy, world *w);
    gen_ref_handler (world *w);
    virtual ~gen_ref_handler (void);

    pco_ref_t get_ref (uint8_t tn, struct con_id* cp);
    pco_ref_t get_ref (uint8_t tn, uint8_t obj, uint8_t sub_ch = 0, uint8_t vsc = 0);

    void config (uint8_t tn, chan_comb_enum cc, bool cbch);
    bool check_tn_config (uint8_t tn);

    uint8_t get_tn (pco_ref_t ref);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_channel_fas (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);

    // Return refs for all clusters for the appointed TN
    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs);

    // Return refs for all objects for the appointed TN
    // Not FAS, SCH, IDLE
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);

    // All refs for the appointed TN
    uint8_t get_refs_tn (uint8_t tn, pco_ref_t* refs);

    virtual uint8_t get_sub_ch (pco_ref_t ref);
    virtual uint8_t get_vsc (pco_ref_t ref);

  protected :
    world *w;

  private :
    virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc = 0); // Override !!
    uint8_t prep_sub_ch (uint8_t obj, uint8_t sub_ch);

    gen_ref_handler* ref_handlers [8];
    gen_ref_handler* cc_i;
    gen_ref_handler* cc_i_ii;
    gen_ref_handler* cc_i_ii_vamos;
    gen_ref_handler* cc_iv;
    gen_ref_handler* cc_v;
    gen_ref_handler* cc_vi;
    gen_ref_handler* cc_vii;
    gen_ref_handler* cc_ec;

    typedef union ref_index
    {
      struct
      {
#ifdef G_BIG_ENDIAN
        unsigned tn       : 3;
        unsigned not_used : 5;
#else
        unsigned not_used : 5;
        unsigned tn       : 3;   // 0 - 7
#endif
      } field;
      uint8_t byte;
    } ref_index_t;
};





