
#include "test.h"

#include<iostream>


#define BITFIELD_32  unsigned
#define BITFIELD_16  unsigned short
#define BITFIELD_8   unsigned char
#define Sign_BITFIELD_16  signed short

#define VSC0 0
#define VSC1 1

#define TAROT_CDM_SIZE           0x14000

#define HYPERFRAME    2715648

typedef struct
{
#ifdef G_BIG_ENDIAN
    unsigned tn         : 3;   // 0 - 7
    unsigned obj_type   : 2;   // Main, Associated, Misc, Cluster
    unsigned sub_ch     : 3;   // 0 or Misc IDLE/FAS channels
#else
    BITFIELD_8 sub_ch   : 3;   // 0 or Misc IDLE/FAS channels
    BITFIELD_8 obj_type : 2;   // Main, Associated, Misc, Cluster
    BITFIELD_8 tn       : 3;   // 0 - 7
#endif
} field_t;
/*****************************************************************************
 * ref_handler_cc_i
 ****************************************************************************/
class ref_handler_cc_i : public gen_ref_handler
{
  public :
    ref_handler_cc_i (world *w);

    virtual ~ref_handler_cc_i (void);

  virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc = 0);
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_channel_fas (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_sub_ch (pco_ref_t ref);
    virtual uint8_t get_vsc (pco_ref_t ref);

  protected :

  private :
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
 };

/*****************************************************************************
 * ref_handler_cc_i_ii
 ****************************************************************************/
class ref_handler_cc_i_ii : public gen_ref_handler
{
  public :
    ref_handler_cc_i_ii (world *w);

    virtual ~ref_handler_cc_i_ii (void);

    virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc = 0);
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_channel_fas (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_sub_ch (pco_ref_t ref);
    virtual uint8_t get_vsc (pco_ref_t ref);

  protected :

  private :
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
 };

/*****************************************************************************
 * ref_handler_cc_i_ii_vamos
 ****************************************************************************/
class ref_handler_cc_i_ii_vamos : public gen_ref_handler
{
  public :
    ref_handler_cc_i_ii_vamos (world *w);

    virtual ~ref_handler_cc_i_ii_vamos (void);

    virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc);
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_channel_fas (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_sub_ch (pco_ref_t ref);
    virtual uint8_t get_vsc (pco_ref_t ref);

  protected :

  private :
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
 };

/*****************************************************************************
 * ref_handler_cc_iv
 ****************************************************************************/
class ref_handler_cc_iv : public gen_ref_handler
{
  public :
    ref_handler_cc_iv (world *w);

    virtual ~ref_handler_cc_iv (void);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc = 0);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs); // Not to be used
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);      // Not to be used
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);  // Not to be used
    virtual uint8_t get_sub_ch (pco_ref_t ref);          // Not to be used
    virtual uint8_t get_vsc (pco_ref_t ref);

  protected :

  private :
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
};

/*****************************************************************************
 * ref_handler_cc_ec
 ****************************************************************************/
class ref_handler_cc_ec : public gen_ref_handler
{
  public :
    ref_handler_cc_ec (world *w);

    virtual ~ref_handler_cc_ec (void);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc = 0);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs); // Not to be used
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);      // Not to be used
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);  // Not to be used
    virtual uint8_t get_sub_ch (pco_ref_t ref);          // Not to be used
    virtual uint8_t get_vsc (pco_ref_t ref);

  protected :

  private :
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
};

/*****************************************************************************
 * ref_handler_cc_v
 ****************************************************************************/
class ref_handler_cc_v : public gen_ref_handler
{
  public :
    ref_handler_cc_v (world *w);

    virtual ~ref_handler_cc_v (void);

    virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc = 0);
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_sub_ch (pco_ref_t ref);
    virtual uint8_t get_vsc (pco_ref_t ref);
    void set_cbch (bool cbch_ind);

  protected :

  private :
    bool cbch;
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
};

/*****************************************************************************
 * ref_handler_cc_vi
 ****************************************************************************/
class ref_handler_cc_vi : public gen_ref_handler
{
  public :
    ref_handler_cc_vi (world *w);

    virtual ~ref_handler_cc_vi (void);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual pco_ref_t get (uint8_t tn, uint8_t obj, uint8_t sub_ch, uint8_t vsc = 0);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs); // Not to be used
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);      // Not to be used
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);  // Not to be used
    virtual uint8_t get_sub_ch (pco_ref_t ref);          // Not to be used
    virtual uint8_t get_vsc (pco_ref_t ref);

  protected :

  private :
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
};

/*****************************************************************************
 * ref_handler_cc_vii
 ****************************************************************************/
class ref_handler_cc_vii : public gen_ref_handler
{
  public :
    ref_handler_cc_vii (world *w);

    virtual ~ref_handler_cc_vii (void);

    virtual pco_ref_t get (uint8_t tn, uint8_t, uint8_t sub_ch, uint8_t vsc = 0);
    virtual pco_ref_t get_idle_ch_ref (uint8_t tn);
    virtual pco_ref_t get_cl_ref (pco_ref_t chan_ref);

    virtual bool is_channel (pco_ref_t ref);
    virtual bool is_cluster (pco_ref_t ref);

    virtual uint8_t get_clus_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_ext_refs_tn (uint8_t tn, pco_ref_t* refs);
    virtual uint8_t get_sub_ch (pco_ref_t ref);
    virtual uint8_t get_vsc (pco_ref_t ref);
    void set_cbch (bool cbch_ind);

  protected :

  private :
    bool cbch;
    typedef union ref_index
    {
      field_t field;
      uint8_t byte;
    } ref_index_t;
};

gen_ref_handler :: gen_ref_handler (uint8_t dummy, world *w)
{
  this->w       = w;
  cc_i          = NULL;
  cc_i_ii       = NULL;
  cc_i_ii_vamos = NULL;
  cc_iv         = NULL;
  cc_v          = NULL;
  cc_vi         = NULL;
  cc_vii        = NULL;
  cc_ec         = NULL;

}
gen_ref_handler :: gen_ref_handler (world *w)
{
  cc_i          = new ref_handler_cc_i(w);
  cc_i_ii       = new ref_handler_cc_i_ii(w);
  cc_i_ii_vamos = new ref_handler_cc_i_ii_vamos(w);
  cc_iv         = new ref_handler_cc_iv(w);
  cc_v          = new ref_handler_cc_v(w);
  cc_vi         = new ref_handler_cc_vi(w);
  cc_vii        = new ref_handler_cc_vii(w);
  cc_ec         = new ref_handler_cc_ec (w);

  this->w = w;
}

//-----------------------------------------------------------------------------
gen_ref_handler :: ~gen_ref_handler (void)
{
  if (cc_i != NULL) delete cc_i;
  if (cc_i_ii != NULL) delete cc_i_ii;
  if (cc_i_ii_vamos != NULL) delete cc_i_ii_vamos;
  if (cc_iv != NULL) delete cc_iv;
  if (cc_v != NULL) delete cc_v;
  if (cc_vi != NULL) delete cc_vi;
  if (cc_vii != NULL) delete cc_vii;
  if (cc_ec != NULL) delete cc_ec;
}


void gen_ref_handler :: config (uint8_t tn, chan_comb_enum cc, bool cbch)
{
  switch (cc)
  {
    case CHAN_COMB_I :
      ref_handlers [tn] = cc_i;
      return;

    case CHAN_COMB_I_II :
      ref_handlers [tn] = cc_i_ii;
      return;

    case CHAN_COMB_I_II_VAMOS :
      ref_handlers [tn] = cc_i_ii_vamos;
      return;

    case CHAN_COMB_IV :
      ref_handlers [tn] = cc_iv;
      return;

    case CHAN_COMB_V : case CHAN_COMB_V_CBCH :
      ref_handlers [tn] = cc_v;
      return;

    case CHAN_COMB_VI :
      ref_handlers [tn] = cc_vi;
      return;

    case CHAN_COMB_VII : case CHAN_COMB_VII_CBCH :
      ref_handlers [tn] = cc_vii;
      return;

    case CHAN_COMB_EC :
      ref_handlers [tn] = cc_ec;
      return;

    default :
    std::cout<<"error in config!"<<std::endl;
  }
}



bool gen_ref_handler :: check_tn_config (uint8_t tn)
{
  if (ref_handlers [tn] == NULL)
  {
  	std::cout<<"error in check_tn_config!"<<std::endl;
    return (false);
  }

  return (true);
}

uint8_t gen_ref_handler :: get_tn (pco_ref_t ref)
{
  ref_index_t r;

  r.byte = ref;
  return (r.field.tn);
}


bool gen_ref_handler :: is_channel_fas (pco_ref_t ref)
{
  uint8_t tn = get_tn (ref);

  if (!check_tn_config (tn))
  {
    return (false);
  }
  else
  {
    return (ref_handlers [tn]->is_channel_fas (ref));
  }
}


int main(void)
{
	pco_ref_t pco_ref;
	gen_ref_handler *ref_h= new gen_ref_handler();
  bool is_fas = ref_h->is_channel_fas (pco_ref);
  std::cout<<"is_fas="<<is_fas<<std::endl;
  return 0;
	
}


