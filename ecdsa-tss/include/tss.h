#ifndef _TSS_H_
#define _TSS_H_

void* new_keygen(int i, int t, int n);
void free_keygen(void* state);
int keygen_current_round(const void* state);
int keygen_total_rounds(const void* state);
int keygen_party_ind(const void* state);
int keygen_parties(const void* state);
int keygen_wants_to_proceed(const void* state);
int keygen_proceed(void* state);
int keygen_has_outgoing(void* state);
int keygen_is_finished(void* state);
int keygen_pick_output(void* state, char* buf, int max_len);
int keygen_incoming(void* state, const char* msg);
int keygen_outgoing(void* state, char* buf, int max_len);
int keygen_get_state(void* state, char* buf, int max_len);

void* new_offline_stage(int i, const int* s_l, int s_l_len, const char* local_key);
void free_offline_stage(void* state);
int offline_stage_current_round(const void* state);
int offline_stage_total_rounds(const void* state);
int offline_stage_party_ind(const void* state);
int offline_stage_parties(const void* state);
int offline_stage_wants_to_proceed(const void* state);
int offline_stage_proceed(void* state);
int offline_stage_has_outgoing(void* state);
int offline_stage_is_finished(void* state);
//int offline_stage_pick_output(void* state, char* buf, int max_len);
int offline_stage_incoming(void* state, const char* msg);
int offline_stage_outgoing(void* state, char* buf, int max_len);
void* offline_stage_to_sign_manual(void* state, const char* msg_hash);
int sign_manual_get_partial_signature(const void* state, char* buf, int max_len);
int sign_manual_complete(const void* state, char* buf, int max_len);
void free_sign_manual(void* state);

#endif