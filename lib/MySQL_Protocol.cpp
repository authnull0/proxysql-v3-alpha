#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "openssl/rand.h"
#include "proxysql.h"
#include "cpp.h"
#include "re2/re2.h"
#include "re2/regexp.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Variables.h"
#include "MySQL_Protocol.h"
#include <sstream>

//#include <ma_global.h>

extern MySQL_Authentication *GloMyAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern MySQL_Threads_Handler *GloMTH;

#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
#endif /* PROXYSQLCLICKHOUSE */

#ifdef max_allowed_packet
#undef max_allowed_packet
#endif

#ifndef CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x00200000
#endif

#include "proxysql_find_charset.h"

mf_unique_ptr<const char> get_masked_pass(const char* pass) {
	char* tmp_pass = strdup(pass);
	int lpass = strlen(tmp_pass);

	for (int i=2; i<lpass-1; i++) {
		tmp_pass[i] = '*';
	}

	return mf_unique_ptr<const char>(static_cast<const char*>(tmp_pass));
}

extern "C" char * sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen);

static const char *plugins[3] = {
	"mysql_native_password",
	"mysql_clear_password",
	"caching_sha2_password",
};

#include "MySQL_encode.h"

std::string unhex(const std::string& hex) {
	if (hex.size() % 2 || hex.size() == 0) { return {}; };

	string result {};

	for (size_t i = 0; i < hex.size() - 1; i += 2) {
		string hex_char { string { hex[i] } + hex[i+1] };
		uint64_t char_val { 0 };

		std::istringstream stream { hex_char };
		stream >> std::hex >> char_val;

		result += string { static_cast<char>(char_val) };
	}

	return result;
}

char* get_password(account_details_t& ad, PASSWORD_TYPE::E passtype) {
	char* ret = nullptr;

	if (ad.clear_text_password[passtype] == NULL) {
		if (passtype == PASSWORD_TYPE::PRIMARY) {
			if (ad.password) {
				ret = strdup(ad.password);
			}
		} else if (ad.attributes) {
			nlohmann::json attrs = nlohmann::json::parse(ad.attributes, nullptr, false);
			string addl_pass { get_nested_elem_val(attrs, { "additional_password" }, string {}) };
			string uh_addl_pass { unhex(addl_pass) };
			proxy_info("Password info   length:%ld, val:`%s`, addl_val:`%s`\n", uh_addl_pass.length(), uh_addl_pass.c_str(), addl_pass.c_str());
			ret = reinterpret_cast<char*>(strdup(uh_addl_pass.c_str()));
		}
	} else {
		// best password we have; if we were able to derive the clear text password, we provide that
		ret = strdup(ad.clear_text_password[passtype]);

		// Only count one attempt using the cache per connection
		if (passtype == PASSWORD_TYPE::PRIMARY) {
			__sync_add_and_fetch(&MyHGM->status.client_connections_sha2cached, 1);
		}
	}

	return ret;
}

#ifdef DEBUG
void debug_spiffe_id(const unsigned char *user, const char *attributes, int __line, const char *__func) {
	if (attributes!=NULL && strlen(attributes)) {
		json j = nlohmann::json::parse(attributes);
		auto spiffe_id = j.find("spiffe_id");
		if (spiffe_id != j.end()) {
			std::string spiffe_val = j["spiffe_id"].get<std::string>();
			proxy_info("%d:%s(): Attributes for user %s: %s . Spiffe_id: %s\n" , __line, __func, user, attributes, spiffe_val.c_str());
		} else {
			proxy_info("%d:%s(): Attributes for user %s: %s\n" , __line, __func, user, attributes);
		}
	}
}
#endif


void MySQL_Protocol::init(MySQL_Data_Stream **__myds, MySQL_Connection_userinfo *__userinfo, MySQL_Session *__sess) {
	myds=__myds;
	userinfo=__userinfo;
	sess=__sess;
	current_PreStmt=NULL;
}

static unsigned char protocol_version=10;
static uint16_t server_status=SERVER_STATUS_AUTOCOMMIT;

bool MySQL_Protocol::generate_statistics_response(bool send, void **ptr, unsigned int *len) {
// FIXME : this function generates a not useful string. It is a placeholder for now

	char buf1[1000];
	unsigned long long t1=monotonic_time();
	sprintf(buf1,"Uptime: %llu Threads: %d  Questions: %llu  Slow queries: %llu", (t1-GloVars.global.start_time)/1000/1000, MyHGM->status.client_connections , GloMTH->get_status_variable(st_var_queries,p_th_counter::questions) , GloMTH->get_status_variable(st_var_queries_slow,p_th_counter::slow_queries) );
	unsigned char statslen=strlen(buf1);
	mysql_hdr myhdr;
	myhdr.pkt_id=1;
	myhdr.pkt_length=statslen;

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);
	memcpy(_ptr+l,buf1,statslen);

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_EOF(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t warnings, uint16_t status, MySQL_ResultSet *myrs) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=5;
	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr = NULL;
	if (myrs == NULL) {
		_ptr = (unsigned char *)l_alloc(size);
	} else {
		_ptr = myrs->buffer + myrs->buffer_used;
		myrs->buffer_used += size;
	}
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);
	_ptr[l]=0xfe; l++;
	int16_t internal_status = status;
	if (sess) {
		switch (sess->session_type) {
			case PROXYSQL_SESSION_SQLITE:
			case PROXYSQL_SESSION_ADMIN:
			case PROXYSQL_SESSION_STATS:
				internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
				break;
			default:
				break;
		}
	}
	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.no_backslash_escapes) {
			internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
		}
		(*myds)->pkt_sid=sequence_id;
	}
	memcpy(_ptr+l, &warnings, sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l, &internal_status, sizeof(uint16_t));
	
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		switch ((*myds)->DSS) {
			case STATE_COLUMN_DEFINITION:
				(*myds)->DSS=STATE_EOF1;
				break;
			case STATE_ROW:
				(*myds)->DSS=STATE_EOF2;
				break;
			default:
				//assert(0);
				break;
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (*myds) {
		(*myds)->pkt_sid=sequence_id;
	}
	return true;
}

bool MySQL_Protocol::generate_pkt_ERR(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint16_t error_code, char *sql_state, const char *sql_message, bool track) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	mysql_hdr myhdr;
	uint32_t sql_message_len=( sql_message ? strlen(sql_message) : 0 );
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=1+sizeof(uint16_t)+1+5+sql_message_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);
	_ptr[l]=0xff; l++;
	memcpy(_ptr+l, &error_code, sizeof(uint16_t)); l+=sizeof(uint16_t);
	_ptr[l]='#'; l++;
	memcpy(_ptr+l, sql_state, 5); l+=5;
	if (sql_message) memcpy(_ptr+l, sql_message, sql_message_len);
	
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		switch ((*myds)->DSS) {
			case STATE_CLIENT_HANDSHAKE:
			case STATE_QUERY_SENT_DS:
			case STATE_QUERY_SENT_NET:
			case STATE_ERR:
				(*myds)->DSS=STATE_ERR;
				break;
			case STATE_OK:
				break;
			case STATE_SLEEP:
				if ((*myds)->sess->session_fast_forward==true) { // see issue #733
					break;
				}
			default:
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (track)
		if (*myds)
			if ((*myds)->sess)
				if ((*myds)->sess->thread)
					(*myds)->sess->thread->status_variables.stvar[st_var_generated_pkt_err]++;
	if (*myds) {
		(*myds)->pkt_sid=sequence_id;
	}
	return true;
}

void MySQL_Protocol::generate_one_byte_pkt(unsigned char b) {
	assert((*myds) != NULL);
	uint8_t sequence_id;
	sequence_id = (*myds)->pkt_sid;
	sequence_id++;
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=2;
	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr=(unsigned char *)l_alloc(size);
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);
	_ptr[l]=1;
	l++;
	_ptr[l]=b;
	(*myds)->PSarrayOUT->add((void *)_ptr,size);
	(*myds)->pkt_sid=sequence_id;
}

bool MySQL_Protocol::generate_pkt_OK(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, unsigned int affected_rows, uint64_t last_insert_id, uint16_t status, uint16_t warnings, char *msg, bool eof_identifier) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	char affected_rows_prefix;
	uint8_t affected_rows_len=mysql_encode_length(affected_rows, &affected_rows_prefix);
	char last_insert_id_prefix;
	uint8_t last_insert_id_len=mysql_encode_length(last_insert_id, &last_insert_id_prefix);
	uint32_t msg_len=( msg ? strlen(msg) : 0 );
	char msg_prefix;
	uint8_t msg_len_len=mysql_encode_length(msg_len, &msg_prefix);

	bool client_session_track=false;
	//char gtid_buf[128];
	char gtid_prefix;
	uint8_t gtid_len=0;
	uint8_t gtid_len_len=0;

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=1+affected_rows_len+last_insert_id_len+sizeof(uint16_t)+sizeof(uint16_t)+msg_len;
	if (msg_len) myhdr.pkt_length+=msg_len_len;

	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.client_flag & CLIENT_SESSION_TRACKING) {
			if (mysql_thread___client_session_track_gtid) {
				if (sess) {
					if (sess->gtid_hid >= 0) {
						if (msg_len == 0) {
							myhdr.pkt_length++;
						}
						client_session_track=true;
						gtid_len = strlen(sess->gtid_buf);
						gtid_len_len = mysql_encode_length(gtid_len, &gtid_prefix);
						myhdr.pkt_length += gtid_len_len;
						myhdr.pkt_length += gtid_len;
						myhdr.pkt_length += 4; // headers related to GTID
					}
				}
			}
		}
	}


	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr=(unsigned char *)l_alloc(size);
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);

	/*
	 * Use 0xFE packet header if eof_identifier is true.
	 * OK packet with 0xFE replaces EOF packet for clients
	 * supporting CLIENT_DEPRECATE_EOF flag
	 */
	if (eof_identifier)
		_ptr[l]=0xFE;
	else
		_ptr[l]=0x00;

	l++;
	l+=write_encoded_length(_ptr+l, affected_rows, affected_rows_len, affected_rows_prefix);
	l+=write_encoded_length(_ptr+l, last_insert_id, last_insert_id_len, last_insert_id_prefix);
	int16_t internal_status = status;
	if (sess) {
		switch (sess->session_type) {
			case PROXYSQL_SESSION_SQLITE:
			case PROXYSQL_SESSION_ADMIN:
			case PROXYSQL_SESSION_STATS:
				internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
				break;
			default:
				break;
		}
		if (sess->session_type == PROXYSQL_SESSION_MYSQL) {
			sess->CurrentQuery.have_affected_rows = true; // if affected rows is set, last_insert_id is set too
			sess->CurrentQuery.affected_rows = affected_rows;
			sess->CurrentQuery.last_insert_id = last_insert_id;
		}
	}
	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.no_backslash_escapes) {
			internal_status |= SERVER_STATUS_NO_BACKSLASH_ESCAPES;
		}
	}
	if (gtid_len == 0) {
		// Remove 'SERVER_SESSION_STATE_CHANGED', since we don't track this info unless GTID related
		internal_status &= ~SERVER_SESSION_STATE_CHANGED;
	}
	memcpy(_ptr+l, &internal_status, sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l, &warnings, sizeof(uint16_t)); l+=sizeof(uint16_t);
	if (msg && strlen(msg)) {
		l+=write_encoded_length(_ptr+l, msg_len, msg_len_len, msg_prefix);
		memcpy(_ptr+l, msg, msg_len);
	}
	l+=msg_len;
	if (client_session_track == true) {
		if (msg_len == 0) {
			_ptr[l]=0x00; l++;
		}
		if (gtid_len) {
			unsigned char gtid_prefix_h1 = gtid_len+2;
			unsigned char state_change_prefix = gtid_prefix_h1+2;
			_ptr[l] = state_change_prefix; l++;
			_ptr[l]=0x03; l++; // SESSION_TRACK_GTIDS
			_ptr[l] = gtid_prefix_h1; l++;
			_ptr[l]=0x00; l++;
			// l+=write_encoded_length(_ptr+l, gtid_len, gtid_len_len, gtid_prefix); // overcomplicated
			_ptr[l] = gtid_len; l++;
			memcpy(_ptr+l, sess->gtid_buf, gtid_len);
		}
	}
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		switch ((*myds)->DSS) {
			case STATE_CLIENT_HANDSHAKE:
			case STATE_QUERY_SENT_DS:
			case STATE_QUERY_SENT_NET:
				(*myds)->DSS=STATE_OK;
				break;
			case STATE_OK:
				break;
			case STATE_ROW:
				if (eof_identifier)
					(*myds)->DSS=STATE_EOF2;
				else
					// LCOV_EXCL_START
					assert(0);
					// LCOV_EXCL_STOP
				break;
			default:
				// LCOV_EXCL_START
				assert(0);
				// LCOV_EXCL_STOP
		}
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (*myds) {
		(*myds)->pkt_sid=sequence_id;
	}
	return true;
}

bool MySQL_Protocol::generate_pkt_column_count(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, uint64_t count, MySQL_ResultSet *myrs) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}

	char count_prefix=0;
	uint8_t count_len=mysql_encode_length(count, &count_prefix);

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=count_len;
  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
//  unsigned char *_ptr=(unsigned char *)l_alloc(size);
  unsigned char *_ptr = NULL;
	if (myrs) {
		if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the buffer, add the data to it
			_ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += size;
		} else {
			// there is no space in the buffer, we flush the buffer and recreate it
			myrs->buffer_to_PSarrayOut();
			// now we can check again if there is space in the buffer
			if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
				// there is space in the NEW buffer, add the data to it
				_ptr = myrs->buffer + myrs->buffer_used;
				myrs->buffer_used += size;
			} else {
				// a new buffer is not enough to store the new row
				_ptr=(unsigned char *)l_alloc(size);
			}
		}
	} else {
		_ptr=(unsigned char *)l_alloc(size);
	}
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);

	l+=write_encoded_length(_ptr+l, count, count_len, count_prefix);

	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (myrs) {
		if (_ptr >= myrs->buffer && _ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT.add(_ptr,size);
		}
	}
	return true;
}


// this is an optimized version of generate_pkt_field() that uses MYSQL_FIELD
// in order to avoid recomputing the length of the various fields
// it also cannot handle field_list
bool MySQL_Protocol::generate_pkt_field2(void **ptr, unsigned int *len, uint8_t sequence_id, MYSQL_FIELD *field, MySQL_ResultSet *myrs) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	//char *def=(char *)"def";
	//uint32_t def_strlen = field->catalog_length;
	char def_prefix;
	uint8_t def_len=mysql_encode_length(field->catalog_length, &def_prefix);

	//uint32_t schema_strlen=strlen(schema);
	char schema_prefix;
	uint8_t schema_len=mysql_encode_length(field->db_length, &schema_prefix);

	//uint32_t table_strlen=strlen(table);
	char table_prefix;
	uint8_t table_len=mysql_encode_length(field->table_length, &table_prefix);

	//uint32_t org_table_strlen=strlen(org_table);
	char org_table_prefix;
	uint8_t org_table_len=mysql_encode_length(field->org_table_length, &org_table_prefix);

	//uint32_t name_strlen=strlen(name);
	char name_prefix;
	uint8_t name_len=mysql_encode_length(field->name_length, &name_prefix);

	//uint32_t org_name_strlen=strlen(org_name);
	char org_name_prefix;
	uint8_t org_name_len=mysql_encode_length(field->org_name_length, &org_name_prefix);

/*
	char defvalue_length_prefix;
	uint8_t defvalue_length_len=0;
	if (field_list) {
		defvalue_length_len=mysql_encode_length(field->def_length, &defvalue_length_prefix);
	}
*/
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length = def_len + field->catalog_length
		+ schema_len + field->db_length
		+ table_len + field->table_length
		+ org_table_len + field->org_table_length
		+ name_len + field->name_length
		+ org_name_len + field->org_name_length
		+ 1  // filler
		+ sizeof(uint16_t) // charset
		+ sizeof(uint32_t) // column_length
		+ sizeof(uint8_t)  // type
		+ sizeof(uint16_t) // flags
		+ sizeof(uint8_t)  // decimals
		+ 2; // filler
/*
	if (field_list) {
		myhdr.pkt_length += defvalue_length_len + strlen(defvalue);
	}
*/
	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr = NULL;
/* myrs always passed
	if (myrs) {
*/
		if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the buffer, add the data to it
			_ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += size;
		} else {
			// there is no space in the buffer, we flush the buffer and recreate it
			myrs->buffer_to_PSarrayOut();
			// now we can check again if there is space in the buffer
			if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
				// there is space in the NEW buffer, add the data to it
				_ptr = myrs->buffer + myrs->buffer_used;
				myrs->buffer_used += size;
			} else {
				// a new buffer is not enough to store the new row
				_ptr=(unsigned char *)l_alloc(size);
			}
		}
/* myrs always passed
	} else {
		_ptr=(unsigned char *)l_alloc(size);
	}
*/
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);

	l+=write_encoded_length_and_string(_ptr+l, field->catalog_length, def_len, def_prefix, field->catalog);
	l+=write_encoded_length_and_string(_ptr+l, field->db_length, schema_len, schema_prefix, field->db);
	l+=write_encoded_length_and_string(_ptr+l, field->table_length, table_len, table_prefix, field->table);
	l+=write_encoded_length_and_string(_ptr+l, field->org_table_length, org_table_len, org_table_prefix, field->org_table);
	l+=write_encoded_length_and_string(_ptr+l, field->name_length, name_len, name_prefix, field->name);
	l+=write_encoded_length_and_string(_ptr+l, field->org_name_length, org_name_len, org_name_prefix, field->org_name);
	_ptr[l]=0x0c; l++;
	memcpy(_ptr+l,&field->charsetnr,sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l,&field->length,sizeof(uint32_t)); l+=sizeof(uint32_t);
	_ptr[l]=field->type; l++;
	memcpy(_ptr+l,&field->flags,sizeof(uint16_t)); l+=sizeof(uint16_t);
	_ptr[l]=field->decimals; l++;
	_ptr[l]=0x00; l++;
	_ptr[l]=0x00; l++;
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
/* myrs always passed
	if (myrs) {
*/
		if (_ptr >= myrs->buffer && _ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT.add(_ptr,size);
		}
/* myrs always passed
	}
*/
	return true;
}

bool MySQL_Protocol::generate_pkt_field(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, char *schema, char *table, char *org_table, char *name, char *org_name, uint16_t charset, uint32_t column_length, uint8_t type, uint16_t flags, uint8_t decimals, bool field_list, uint64_t defvalue_length, char *defvalue, MySQL_ResultSet *myrs) {

	if ((*myds)->sess->mirror==true) {
		return true;
	}
	char *def=(char *)"def";
	uint32_t def_strlen=strlen(def);
	char def_prefix;
	uint8_t def_len=mysql_encode_length(def_strlen, &def_prefix);

	uint32_t schema_strlen=strlen(schema);
	char schema_prefix;
	uint8_t schema_len=mysql_encode_length(schema_strlen, &schema_prefix);

	uint32_t table_strlen=strlen(table);
	char table_prefix;
	uint8_t table_len=mysql_encode_length(table_strlen, &table_prefix);

	uint32_t org_table_strlen=strlen(org_table);
	char org_table_prefix;
	uint8_t org_table_len=mysql_encode_length(org_table_strlen, &org_table_prefix);

	uint32_t name_strlen=strlen(name);
	char name_prefix;
	uint8_t name_len=mysql_encode_length(name_strlen, &name_prefix);

	uint32_t org_name_strlen=strlen(org_name);
	char org_name_prefix;
	uint8_t org_name_len=mysql_encode_length(org_name_strlen, &org_name_prefix);


	char defvalue_length_prefix;
	uint8_t defvalue_length_len=mysql_encode_length(defvalue_length, &defvalue_length_prefix);

	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length = def_len + def_strlen
		+ schema_len + schema_strlen
		+ table_len + table_strlen
		+ org_table_len + org_table_strlen
		+ name_len + name_strlen
		+ org_name_len + org_name_strlen
		+ 1  // filler
		+ sizeof(uint16_t) // charset
		+ sizeof(uint32_t) // column_length
		+ sizeof(uint8_t)  // type
		+ sizeof(uint16_t) // flags
		+ sizeof(uint8_t)  // decimals
		+ 2; // filler
	if (field_list) {
		myhdr.pkt_length += defvalue_length_len + strlen(defvalue);
	} //else myhdr.pkt_length++;

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr = NULL;
	if (myrs) {
		if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the buffer, add the data to it
			_ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += size;
		} else {
			// there is no space in the buffer, we flush the buffer and recreate it
			myrs->buffer_to_PSarrayOut();
			// now we can check again if there is space in the buffer
			if ( size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
				// there is space in the NEW buffer, add the data to it
				_ptr = myrs->buffer + myrs->buffer_used;
				myrs->buffer_used += size;
			} else {
				// a new buffer is not enough to store the new row
				_ptr=(unsigned char *)l_alloc(size);
			}
		}
	} else {
		_ptr=(unsigned char *)l_alloc(size);
	}
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l=sizeof(mysql_hdr);

	l+=write_encoded_length_and_string(_ptr+l, def_strlen, def_len, def_prefix, def);
	l+=write_encoded_length_and_string(_ptr+l, schema_strlen, schema_len, schema_prefix, schema);
	l+=write_encoded_length_and_string(_ptr+l, table_strlen, table_len, table_prefix, table);
	l+=write_encoded_length_and_string(_ptr+l, org_table_strlen, org_table_len, org_table_prefix, org_table);
	l+=write_encoded_length_and_string(_ptr+l, name_strlen, name_len, name_prefix, name);
	l+=write_encoded_length_and_string(_ptr+l, org_name_strlen, org_name_len, org_name_prefix, org_name);
	_ptr[l]=0x0c; l++;
	memcpy(_ptr+l,&charset,sizeof(uint16_t)); l+=sizeof(uint16_t);
	memcpy(_ptr+l,&column_length,sizeof(uint32_t)); l+=sizeof(uint32_t);
	_ptr[l]=type; l++;
	memcpy(_ptr+l,&flags,sizeof(uint16_t)); l+=sizeof(uint16_t);
	_ptr[l]=decimals; l++;
	_ptr[l]=0x00; l++;
	_ptr[l]=0x00; l++;
	if (field_list) {
		l+=write_encoded_length_and_string(_ptr+l, strlen(defvalue), defvalue_length_len, defvalue_length_prefix, defvalue);
	} 
	//else _ptr[l]=0x00;
	//else fprintf(stderr,"current deflen=%d, defstrlen=%d, namelen=%d, namestrlen=%d, l=%d\n", def_len, def_strlen, name_len, name_strlen, l);
	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	if (myrs) {
		if (_ptr >= myrs->buffer && _ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT.add(_ptr,size);
		}
	}
	return true;
}


// FIXME FIXME function not completed yet!
// see https://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
bool MySQL_Protocol::generate_STMT_PREPARE_RESPONSE(uint8_t sequence_id, MySQL_STMT_Global_info *stmt_info, uint32_t _stmt_id) {
	uint8_t sid=sequence_id;
	uint16_t i;
	char *okpack=(char *)malloc(16); // first packet
	mysql_hdr hdr;
	hdr.pkt_id=sid;
	hdr.pkt_length=12;
	memcpy(okpack,&hdr,sizeof(mysql_hdr)); // copy header
	okpack[4]=0;
	okpack[13]=0;
	okpack[15]=0;
	pthread_rwlock_rdlock(&stmt_info->rwlock_);
	if (_stmt_id) {
		memcpy(okpack+5,&_stmt_id,sizeof(uint32_t));
	} else {
		memcpy(okpack+5,&stmt_info->statement_id,sizeof(uint32_t));
	}
	memcpy(okpack+9,&stmt_info->num_columns,sizeof(uint16_t));
	memcpy(okpack+11,&stmt_info->num_params,sizeof(uint16_t));
	memcpy(okpack+14,&stmt_info->warning_count,sizeof(uint16_t));
	(*myds)->PSarrayOUT->add((void *)okpack,16);
	sid++;
	int setStatus = SERVER_STATUS_AUTOCOMMIT;
	if (myds) {
		setStatus = 0;
		unsigned int Trx_id = (*myds)->sess->FindOneActiveTransaction();
		setStatus = (Trx_id >= 0 ? SERVER_STATUS_IN_TRANS : 0 );
		if ((*myds)->sess->autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
	}
	bool deprecate_eof_active = false;
	if (*myds && (*myds)->myconn) {
		if ((*myds)->myconn->options.client_flag & CLIENT_DEPRECATE_EOF) {
			deprecate_eof_active = true;
		}
	}
	if (stmt_info->num_params) {
		for (i=0; i<stmt_info->num_params; i++) {
			generate_pkt_field(true,NULL,NULL,sid,
				(char *)"", (char *)"", (char *)"", (char *)"?", (char *)"",
				63,0,253,128,0,false,0,NULL); // NOTE: charset is 63 = binary !
			sid++;
		}
		if (!deprecate_eof_active) {
			generate_pkt_EOF(true,NULL,NULL,sid,0,setStatus);
			sid++;
		}
	}
	if (stmt_info->num_columns) {
		for (i=0; i<stmt_info->num_columns; i++) {
			MYSQL_FIELD *fd=stmt_info->fields[i];
			generate_pkt_field(true,NULL,NULL,sid,
				fd->db,
				fd->table, fd->org_table,
				fd->name, fd->org_name,
				fd->charsetnr, fd->length, fd->type, fd->flags, fd->decimals, false,0,NULL);
			sid++;
		}
		if (!deprecate_eof_active) {
			generate_pkt_EOF(true,NULL,NULL,sid,0,setStatus);
			sid++;
		}
	}
	pthread_rwlock_unlock(&stmt_info->rwlock_);
	return true;
}

bool MySQL_Protocol::generate_pkt_row(bool send, void **ptr, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt) {
	int col=0;
	int rowlen=0;
	for (col=0; col<colnums; col++) {
		rowlen+=( fieldstxt[col] ? fieldslen[col]+mysql_encode_length(fieldslen[col],NULL) : 1 );
	}
	mysql_hdr myhdr;
	myhdr.pkt_id=sequence_id;
	myhdr.pkt_length=rowlen;

	unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
	unsigned char *_ptr=(unsigned char *)l_alloc(size);
	memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
	int l=sizeof(mysql_hdr);
	for (col=0; col<colnums; col++) {
		if (fieldstxt[col]) {
			char length_prefix;
			uint8_t length_len=mysql_encode_length(fieldslen[col], &length_prefix);
			l+=write_encoded_length_and_string(_ptr+l,fieldslen[col],length_len, length_prefix, fieldstxt[col]);
		} else {
			_ptr[l]=0xfb;
			l++;
		}
	}
	if (send==true) { (*myds)->PSarrayOUT->add((void *)_ptr,size); }
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

uint8_t MySQL_Protocol::generate_pkt_row3(MySQL_ResultSet *myrs, unsigned int *len, uint8_t sequence_id, int colnums, unsigned long *fieldslen, char **fieldstxt, unsigned long rl) {
	if ((*myds)->sess->mirror==true) {
		return true;
	}
	int col=0;
	unsigned long rowlen=0;
	uint8_t pkt_sid=sequence_id;
	if (rl == 0) {
		// if rl == 0 , we are using text protocol (legacy) therefore we need to compute the size of the row
		for (col=0; col<colnums; col++) {
			rowlen+=( fieldstxt[col] ? fieldslen[col]+mysql_encode_length(fieldslen[col],NULL) : 1 );
		}
	} else {
		// we already know the size of the row
		rowlen=rl;
	}
	PtrSize_t pkt;
	pkt.size=rowlen+sizeof(mysql_hdr);
	if ( pkt.size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
		// there is space in the buffer, add the data to it
		pkt.ptr = myrs->buffer + myrs->buffer_used;
		myrs->buffer_used += pkt.size;
	} else {
		// there is no space in the buffer, we flush the buffer and recreate it
		myrs->buffer_to_PSarrayOut();
		// now we can check again if there is space in the buffer
		if ( pkt.size<=(RESULTSET_BUFLEN-myrs->buffer_used) ) {
			// there is space in the NEW buffer, add the data to it
			pkt.ptr = myrs->buffer + myrs->buffer_used;
			myrs->buffer_used += pkt.size;
		} else {
			// a new buffer is not enough to store the new row
			pkt.ptr=l_alloc(pkt.size);
		}
	}
	int l=sizeof(mysql_hdr);
	if (rl == 0) {
		for (col=0; col<colnums; col++) {
			if (fieldstxt[col]) {
				char length_prefix;
				uint8_t length_len=mysql_encode_length(fieldslen[col], &length_prefix);
				l+=write_encoded_length_and_string((unsigned char *)pkt.ptr+l,fieldslen[col],length_len, length_prefix, fieldstxt[col]);
			} else {
				char *_ptr=(char *)pkt.ptr;
				_ptr[l]=0xfb;
				l++;
			}
		}
	} else {
		memcpy((unsigned char *)pkt.ptr+l, fieldstxt, rl);
	}
	if (pkt.size < (0xFFFFFF+sizeof(mysql_hdr))) {
		mysql_hdr myhdr;
		myhdr.pkt_id=pkt_sid;
		myhdr.pkt_length=rowlen;
		memcpy(pkt.ptr, &myhdr, sizeof(mysql_hdr));
		if (pkt.ptr >= myrs->buffer && pkt.ptr < myrs->buffer+RESULTSET_BUFLEN) {
			// we are writing within the buffer, do not add to PSarrayOUT
		} else {
			// we are writing outside the buffer, add to PSarrayOUT
			myrs->PSarrayOUT.add(pkt.ptr,pkt.size);
		}
	} else {
		unsigned int left=pkt.size;
		unsigned int copied=0;
		while (left>=(0xFFFFFF+sizeof(mysql_hdr))) {
			PtrSize_t pkt2;
			pkt2.size=0xFFFFFF+sizeof(mysql_hdr);
			pkt2.ptr=l_alloc(pkt2.size);
			memcpy((char *)pkt2.ptr+sizeof(mysql_hdr), (char *)pkt.ptr+sizeof(mysql_hdr)+copied, 0xFFFFFF);
			mysql_hdr myhdr;
			myhdr.pkt_id=pkt_sid;
			pkt_sid++;
			myhdr.pkt_length=0xFFFFFF;
			memcpy(pkt2.ptr, &myhdr, sizeof(mysql_hdr));
			// we are writing a large packet (over 16MB), we assume we are always outside the buffer
			myrs->PSarrayOUT.add(pkt2.ptr,pkt2.size);
			copied+=0xFFFFFF;
			left-=0xFFFFFF;
		}
		PtrSize_t pkt2;
		pkt2.size=left;
		pkt2.ptr=l_alloc(pkt2.size);
		memcpy((char *)pkt2.ptr+sizeof(mysql_hdr), (char *)pkt.ptr+sizeof(mysql_hdr)+copied, left-sizeof(mysql_hdr));
		mysql_hdr myhdr;
		myhdr.pkt_id=pkt_sid;
		myhdr.pkt_length=left-sizeof(mysql_hdr);
		memcpy(pkt2.ptr, &myhdr, sizeof(mysql_hdr));
		// we are writing a large packet (over 16MB), we assume we are always outside the buffer
		myrs->PSarrayOUT.add(pkt2.ptr,pkt2.size);
	}
	if (len) { *len=pkt.size+(pkt_sid-sequence_id)*sizeof(mysql_hdr); }
	if (pkt.size >= (0xFFFFFF+sizeof(mysql_hdr))) {
		l_free(pkt.size,pkt.ptr);
	}
	return pkt_sid;
}

bool MySQL_Protocol::generate_pkt_auth_switch_request(bool send, void **ptr, unsigned int *len) {
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating auth switch request pkt\n");
	const char *plugins_names[3] = { "mysql_native_password", "mysql_clear_password", "caching_sha2_password" };
	size_t plugins_lens[3];
	for (int i=0; i<3; i++)
		plugins_lens[i] = strlen(plugins_names[i]);
  mysql_hdr myhdr;
  myhdr.pkt_id=2;
	if ((*myds)->encrypted) {
		myhdr.pkt_id++;
	}

	// Check if a 'COM_CHANGE_USER' Auth Switch is being performed in session
	if ((*myds)->sess->change_user_auth_switch) {
		myhdr.pkt_id=1;
	}

	switch((*myds)->switching_auth_type) {
		case AUTH_MYSQL_NATIVE_PASSWORD:
			myhdr.pkt_length=1 // fe
				+ (plugins_lens[0]+1)
				+ 20 // scramble
				+ 1; // 00
			break;
		case AUTH_MYSQL_CLEAR_PASSWORD:
			myhdr.pkt_length=1 // fe
				+ (plugins_lens[1]+1)
				+ 1; // 00
			break;
		case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
			myhdr.pkt_length=1 // fe
				+ (plugins_lens[2]+1)
				+ 20 // scramble
				+ 1; // 00
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
			break;
	}

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)malloc(size);
	memset(_ptr,0,size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l;
  l=sizeof(mysql_hdr);
  _ptr[l]=0xfe; l++; //0xfe

	switch((*myds)->switching_auth_type) {
		case AUTH_MYSQL_NATIVE_PASSWORD:
			memcpy(_ptr+l,plugins_names[0],plugins_lens[0]);
			l+=plugins_lens[0];
			_ptr[l]=0x00; l++;
			memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 20); l+=20;
			break;
		case AUTH_MYSQL_CLEAR_PASSWORD:
			memcpy(_ptr+l,plugins_names[1],plugins_lens[1]);
			l+=plugins_lens[1];
			_ptr[l]=0x00; l++;
			break;
		case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
			memcpy(_ptr+l,plugins_names[2],plugins_lens[2]);
			l+=plugins_lens[2];
			_ptr[l]=0x00; l++;
			memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 20); l+=20;
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
			break;
	}
  _ptr[l]=0x00; //l+=1; //0x00
	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		(*myds)->DSS=STATE_SERVER_HANDSHAKE;
		(*myds)->sess->status=CONNECTING_CLIENT;
	}
	(*myds)->switching_auth_sent = (*myds)->switching_auth_type;

	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

bool MySQL_Protocol::generate_pkt_initial_handshake(bool send, void **ptr, unsigned int *len, uint32_t *_thread_id, bool deprecate_eof_active) {
	int use_plugin_id = mysql_thread___default_authentication_plugin_int;
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Generating handshake pkt\n");
	assert(use_plugin_id == 0 || use_plugin_id == 2 ); // mysql_native_password or caching_sha2_password
  mysql_hdr myhdr;
  myhdr.pkt_id=0;
  myhdr.pkt_length=sizeof(protocol_version)
    + (strlen(mysql_thread___server_version)+1)
    + sizeof(uint32_t)  // thread_id
    + 8  // scramble1
    + 1  // 0x00
    //+ sizeof(glovars.server_capabilities)
    //+ sizeof(glovars.server_language)
    //+ sizeof(glovars.server_status)
    + sizeof(mysql_thread___server_capabilities)/2
    + sizeof(uint8_t) // charset in handshake is 1 byte
    + sizeof(server_status)
    + 3 // unknown stuff
    + 10 // filler
    + 12 // scramble2
    + 1  // 0x00
//    + (strlen("mysql_native_password")+1);
    + (strlen(plugins[use_plugin_id])+1);
	sent_auth_plugin_id = (enum proxysql_auth_plugins)use_plugin_id;

  unsigned int size=myhdr.pkt_length+sizeof(mysql_hdr);
  unsigned char *_ptr=(unsigned char *)malloc(size);
	memset(_ptr,0,size);
  memcpy(_ptr, &myhdr, sizeof(mysql_hdr));
  int l;
  l=sizeof(mysql_hdr);
  uint32_t thread_id=__sync_fetch_and_add(&glovars.thread_id,1);
	if (thread_id==0) {
		thread_id=__sync_fetch_and_add(&glovars.thread_id,1); // again!
	}
	*_thread_id=thread_id;

  rand_struct rand_st;
  //randominit(&rand_st,rand(),rand());
  rand_st.max_value= 0x3FFFFFFFL;
  rand_st.max_value_dbl=0x3FFFFFFFL;
  rand_st.seed1=rand()%rand_st.max_value;
  rand_st.seed2=rand()%rand_st.max_value;

  memcpy(_ptr+l, &protocol_version, sizeof(protocol_version)); l+=sizeof(protocol_version);
  memcpy(_ptr+l, mysql_thread___server_version, strlen(mysql_thread___server_version)); l+=strlen(mysql_thread___server_version)+1;
  memcpy(_ptr+l, &thread_id, sizeof(uint32_t)); l+=sizeof(uint32_t);
//#ifdef MARIADB_BASE_VERSION
//  proxy_create_random_string(myds->myconn->myconn.scramble_buff+0,8,(struct my_rnd_struct *)&rand_st);
//#else
  proxy_create_random_string((*myds)->myconn->scramble_buff+0,8,(struct rand_struct *)&rand_st);
//#endif

  int i;

//  for (i=0;i<8;i++) {
//    if ((*myds)->myconn->scramble_buff[i]==0) {
//      (*myds)->myconn->scramble_buff[i]='a';
//    }
//  }

	memcpy(_ptr+l, (*myds)->myconn->scramble_buff+0, 8); l+=8;
	_ptr[l]=0x00; l+=1; //0x00
	if (mysql_thread___have_compress) {
		mysql_thread___server_capabilities |= CLIENT_COMPRESS;
	} else {
		mysql_thread___server_capabilities &= ~CLIENT_COMPRESS;
	}
	if (mysql_thread___have_ssl==true || mysql_thread___default_authentication_plugin_int==2) {
		// we enable SSL for client connections for either of these 2 conditions:
		// - have_ssl is enabled
		// - default_authentication_plugin=caching_sha2_password
		mysql_thread___server_capabilities |= CLIENT_SSL;
	} else {
		mysql_thread___server_capabilities &= ~CLIENT_SSL;
	}
	mysql_thread___server_capabilities |= CLIENT_LONG_FLAG;
	mysql_thread___server_capabilities |= CLIENT_MYSQL | CLIENT_PLUGIN_AUTH | CLIENT_RESERVED;
	if (mysql_thread___enable_client_deprecate_eof) {
		mysql_thread___server_capabilities |= CLIENT_DEPRECATE_EOF;
	} else {
		mysql_thread___server_capabilities &= ~CLIENT_DEPRECATE_EOF;
	}
	(*myds)->myconn->options.server_capabilities=mysql_thread___server_capabilities;
  memcpy(_ptr+l,&mysql_thread___server_capabilities, sizeof(mysql_thread___server_capabilities)/2); l+=sizeof(mysql_thread___server_capabilities)/2;
  const MARIADB_CHARSET_INFO *ci = NULL;
  ci = proxysql_find_charset_collate(mysql_thread___default_variables[SQL_COLLATION_CONNECTION]);
  if (!ci) {
		// LCOV_EXCL_START
	  proxy_error("Cannot find character set for name [%s]. Configuration error. Check [%s] global variable.\n",
			  mysql_thread___default_variables[SQL_CHARACTER_SET], mysql_tracked_variables[SQL_CHARACTER_SET].internal_variable_name);
	  assert(0);
		// LCOV_EXCL_STOP
  }
  uint8_t uint8_charset = ci->nr & 255;
  memcpy(_ptr+l,&uint8_charset, sizeof(uint8_charset)); l+=sizeof(uint8_charset);
  memcpy(_ptr+l,&server_status, sizeof(server_status)); l+=sizeof(server_status);
	uint32_t extended_capabilities = CLIENT_MULTI_RESULTS | CLIENT_MULTI_STATEMENTS | CLIENT_PS_MULTI_RESULTS |
		CLIENT_PLUGIN_AUTH | CLIENT_SESSION_TRACKING | CLIENT_REMEMBER_OPTIONS;
	// we conditionally reply the client specifying in 'server_capabilities' that
	// 'CLIENT_DEPRECATE_EOF' is available if explicitly enabled by 'mysql-enable_client_deprecate_eof'
	// variable. This is the first step of ensuring that client connections doesn't
	// enable 'CLIENT_DEPRECATE_EOF' unless explicitly stated by 'mysql-enable_client_deprecate_eof'.
	// Second step occurs during client handshake response (process_pkt_handshake_response).
	if (deprecate_eof_active && mysql_thread___enable_client_deprecate_eof) {
		extended_capabilities |= CLIENT_DEPRECATE_EOF;
	}
	// Copy the 'capability_flags_2'
	uint16_t upper_word = static_cast<uint16_t>(extended_capabilities >> 16);
	memcpy(_ptr+l, static_cast<void*>(&upper_word), sizeof(upper_word)); l += sizeof(upper_word);
	// Copy the 'auth_plugin_data_len'. Hardcoded due to 'CLIENT_PLUGIN_AUTH' always enabled and reported
	// as 'mysql_native_password'.
	uint8_t auth_plugin_data_len = 21;
	memcpy(_ptr+l, &auth_plugin_data_len, sizeof(auth_plugin_data_len)); l += sizeof(auth_plugin_data_len);

  for (i=0;i<10; i++) { _ptr[l]=0x00; l++; } //filler
  //create_random_string(mypkt->data+l,12,(struct my_rnd_struct *)&rand_st); l+=12;
//#ifdef MARIADB_BASE_VERSION
//  proxy_create_random_string(myds->myconn->myconn.scramble_buff+8,12,(struct my_rnd_struct *)&rand_st);
//#else
  proxy_create_random_string((*myds)->myconn->scramble_buff+8,12,(struct rand_struct *)&rand_st);
//#endif
  //create_random_string(scramble_buf+8,12,&rand_st);

//  for (i=8;i<20;i++) {
//    if ((*myds)->myconn->scramble_buff[i]==0) {
//      (*myds)->myconn->scramble_buff[i]='a';
//    }
//  }

  memcpy(_ptr+l, (*myds)->myconn->scramble_buff+8, 12); l+=12;
  l+=1; //0x00
  //memcpy(_ptr+l,"mysql_native_password",strlen("mysql_native_password"));
  memcpy(_ptr+l,plugins[use_plugin_id],strlen(plugins[use_plugin_id]));

	if (send==true) {
		(*myds)->PSarrayOUT->add((void *)_ptr,size);
		(*myds)->DSS=STATE_SERVER_HANDSHAKE;
		(*myds)->sess->status=CONNECTING_CLIENT;
	}
	if (len) { *len=size; }
	if (ptr) { *ptr=(void *)_ptr; }
#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,_ptr,size); }
#endif
	return true;
}

#ifdef PROXYSQLCLICKHOUSE
void ch_account_to_my(account_details_t& account, ch_account_details_t& ch_account) {
    account.username = ch_account.username;
    account.password = ch_account.password;
    account.sha1_pass = ch_account.sha1_pass;
    account.use_ssl = ch_account.use_ssl;
    account.default_hostgroup = ch_account.default_hostgroup;
    account.default_schema = ch_account.default_schema;
    account.schema_locked = ch_account.schema_locked;
    account.transaction_persistent = ch_account.transaction_persistent;
    account.fast_forward = ch_account.fast_forward;
    account.max_connections = ch_account.max_connections;
    account.num_connections_used = ch_account.num_connections_used;

    // Fields that are not present in `ch_account_details_t`
    account.num_connections_used_addl_pass = 0;   // Assuming no additional password used
    account.clear_text_password[0] = nullptr;     // No clear text passwords by default
    account.clear_text_password[1] = nullptr;
    account.__frontend = ch_account.__frontend;   // Copy frontend flag
    account.__backend = ch_account.__backend;     // Copy backend flag
    account.__active = ch_account.__active;       // Copy active flag
    account.attributes = nullptr;                 // No attributes by default
    account.comment = nullptr;                    // No comment by default
}
#endif /* PROXYSQLCLICKHOUSE */

bool MySQL_Protocol::process_pkt_auth_swich_response(unsigned char *pkt, unsigned int len) {
	bool ret=false;
	char *password=NULL;

#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,pkt,len); }
#endif

	if (len!=sizeof(mysql_hdr)+20) {
		return ret;
	}
	mysql_hdr hdr;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	unsigned char pass[128];
	memset(pass,0,128);
	pkt+=sizeof(mysql_hdr);
	memcpy(pass, pkt, 20);

	MyProt_tmp_auth_vars vars1;
	account_details_t account_details {};
	dup_account_details_t dup_details {};
	dup_details.sha1_pass = true;

	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		ch_dup_account_details_t ch_dup_details {};
		ch_dup_details.sha1_pass = true;

		ch_account_details_t ch_account {
			GloClickHouseAuth->lookup((char*)userinfo->username, USERNAME_FRONTEND, ch_dup_details)
		};

		ch_account_to_my(account_details, ch_account);
		password = ch_account.password;
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		account_details = GloMyAuth->lookup((char*)userinfo->username, USERNAME_FRONTEND, dup_details);
		password = account_details.password;
	}
	// FIXME: add support for default schema and fast forward , issues #255 and #256
	// FIXME: not sure if we should also handle user_attributes *here* . For now we pass NULL (no change)
	if (password==NULL) {
		ret=false;
	} else {
			char reply[SHA_DIGEST_LENGTH+1];
			reply[SHA_DIGEST_LENGTH]='\0';

			if (password[0]!='*') { // clear text password
				proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
				if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
					ret=true;
				}
			} else {
				ret=proxy_scramble_sha1((char *)pass,(*myds)->myconn->scramble_buff,password+1, reply);
				if (ret) {
					if (account_details.sha1_pass==NULL) {
						// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
						GloMyAuth->set_SHA1((char *)userinfo->username, USERNAME_FRONTEND,reply);
					}
					if (userinfo->sha1_pass) free(userinfo->sha1_pass);
					userinfo->sha1_pass=sha1_pass_hex(reply);
				}
			}
	}
	free_account_details(account_details);

	return ret;
}

bool MySQL_Protocol::verify_user_pass(
	enum proxysql_session_type session_type,
	const char* password,
	const char* user,
	const char* pass,
	int pass_len,
	const char* sha1_pass,
	const char* auth_plugin
) {
	bool ret = false;

	char reply[SHA_DIGEST_LENGTH+1];
	reply[SHA_DIGEST_LENGTH]='\0';
	auth_plugin_id = AUTH_UNKNOWN_PLUGIN; // default

	if (strncmp((char *)auth_plugin,plugins[0],strlen(plugins[0]))==0) { // mysql_native_password
		auth_plugin_id = AUTH_MYSQL_NATIVE_PASSWORD;
	} else if (strncmp((char *)auth_plugin,plugins[1],strlen(plugins[1]))==0) { // mysql_clear_password
		auth_plugin_id = AUTH_MYSQL_CLEAR_PASSWORD;
	} else if (strncmp((char *)auth_plugin,plugins[2],strlen(plugins[2]))==0) { // caching_sha2_password
		//auth_plugin_id = 2; // FIXME: this is temporary, because yet not supported
		auth_plugin_id = AUTH_MYSQL_CACHING_SHA2_PASSWORD; // FIXME: this is temporary, because yet not supported . It must become 3
	}

	if (password[0]!='*') { // clear text password
		if (auth_plugin_id == 0) { // mysql_native_password
			proxy_scramble(reply, (*myds)->myconn->scramble_buff, password);
			if (memcmp(reply, pass, SHA_DIGEST_LENGTH)==0) {
				ret=true;
			}
		} else if (auth_plugin_id == 1) { // mysql_clear_password
			if (strncmp(password,(char *)pass,strlen(password))==0) {
				ret=true;
			}
		} else if (auth_plugin_id == 2) { // caching_sha2_password
			// ## FIXME: Current limitation
			// For now, if a 'COM_CHANGE_USER' is received with a hashed 'password' for
			// 'caching_sha2_password', we fail to authenticate. This is part of the broader limitation of
			// 'Auth Switch' support for 'caching_sha2_password' (See
			// https://proxysql.com/documentation/authentication-methods/#limitations).
			//
			// ## Future Fix
			// The right approach is to perform an 'Auth Switch Request' or to accept the hash if the clear
			// text password is already known and the hash can be verified. This processing is now performed
			// in 'process_pkt_COM_CHANGE_USER', state at which it should be determine if we can accept the
			// hash, or if we should prepare the state machine for a 'Auth Switch Request'. Progress for this
			// is tracked in https://github.com/sysown/proxysql/issues/4618.
			ret = false;
		} else {
			ret = false;
		}
	} else {
		if (auth_plugin_id == 0) {
			if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) {
				ret=proxy_scramble_sha1((char *)pass,(*myds)->myconn->scramble_buff,password+1, reply);
				if (ret) {
					if (sha1_pass==NULL) {
						GloMyAuth->set_SHA1((char *)user, USERNAME_FRONTEND,reply);
					}
					if (userinfo->sha1_pass) free(userinfo->sha1_pass);
					userinfo->sha1_pass=sha1_pass_hex(reply);
				}
			}
		} else {
			if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , session_type=%d\n", (*myds), (*myds)->sess, user, session_type);
				unsigned char md1_buf[SHA_DIGEST_LENGTH];
				unsigned char md2_buf[SHA_DIGEST_LENGTH];
				SHA1((const unsigned char *)pass,pass_len,md1_buf);
				SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
				char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer

				if (strcasecmp(double_hashed_password,password)==0) {
					ret = true;
					if (sha1_pass==NULL) {
						GloMyAuth->set_SHA1((char *)user, USERNAME_FRONTEND,md1_buf);
					}
					if (userinfo->sha1_pass)
						free(userinfo->sha1_pass);
					userinfo->sha1_pass=sha1_pass_hex((char *)md1_buf);
				} else {
					ret = false;
				}
				free(double_hashed_password);
			}
		}
	}

	return ret;
}

bool MySQL_Protocol::process_pkt_COM_CHANGE_USER(unsigned char *pkt, unsigned int len) {
	bool ret=false;
	int cur=sizeof(mysql_hdr);
	unsigned char *user=NULL;
	char *db=NULL;
	mysql_hdr hdr;
	memcpy(&hdr,pkt,sizeof(mysql_hdr));
	cur++;
	user=pkt+cur;
	cur+=strlen((const char *)user);
	cur++;
	unsigned char pass_len=pkt[cur];
	cur++;
	unsigned char pass[128];
	memset(pass,0,128);
	memcpy(pass, pkt+cur, pass_len);
	cur+=pass_len;
	db=(char *)pkt+cur;
	// Move to field after 'database'
	cur += strlen(db) + 1;
	// Skipt field 'character-set' (size 2)
	cur += 2;
	// Check and get 'Client Auth Plugin' if capability is supported
	char* client_auth_plugin = nullptr;
	if (pkt + len > pkt + cur) {
		int capabilities = (*myds)->sess->client_myds->myconn->options.client_flag;
		if (capabilities & CLIENT_PLUGIN_AUTH) {
			client_auth_plugin = reinterpret_cast<char*>(pkt + cur);
		}
	}
	// Default to 'mysql_native_password' in case 'auth_plugin' is not found.
	if (client_auth_plugin == nullptr) {
		client_auth_plugin = const_cast<char*>("mysql_native_password");
	}
	if (pass_len) {
		if (pass[pass_len-1] == 0) {
			pass_len--; // remove the extra 0 if present
		}
	}

	account_details_t account_details {};
	dup_account_details_t dup_details { false, true, true };
	enum proxysql_session_type session_type = (*myds)->sess->session_type;

	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		ch_dup_account_details_t ch_dup_details { false, true };
		ch_dup_details.sha1_pass = true;

		ch_account_details_t ch_account_details {
			GloClickHouseAuth->lookup((char*)user, USERNAME_FRONTEND, ch_dup_details)
		};

		ch_account_to_my(account_details, ch_account_details);
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		account_details = GloMyAuth->lookup((char *)user, USERNAME_FRONTEND, dup_details);
	}
	// FIXME: add support for default schema and fast forward, see issue #255 and #256
	(*myds)->sess->default_hostgroup=account_details.default_hostgroup;
	(*myds)->sess->transaction_persistent=account_details.transaction_persistent;
	// Could be reached several times before auth completion; allocating attributes should be reset
	if ((*myds)->sess->user_attributes) {
		free((*myds)->sess->user_attributes);
		(*myds)->sess->user_attributes = nullptr;
	}
	(*myds)->sess->user_attributes=account_details.attributes;
	account_details.attributes = nullptr;
	char* password = get_password(account_details, PASSWORD_TYPE::PRIMARY);

	if (password==NULL) {
		ret=false;
	} else {
		if (pass_len==0 && strlen(password)==0) {
			ret=true;
		} else {
			// If pass not sent within 'COM_CHANGE_USER' packet, an 'Auth Switch Request'
			// is required. We default to 'mysql_native_password'. See #3504 for more context.
			if (pass_len == 0) {
				// mysql_native_password
				(*myds)->switching_auth_type = AUTH_MYSQL_NATIVE_PASSWORD;
				// started 'Auth Switch Request' for 'CHANGE_USER' in MySQL_Session.
				(*myds)->sess->change_user_auth_switch = true;

				generate_pkt_auth_switch_request(true, NULL, NULL);
				(*myds)->myconn->userinfo->set((char *)user, NULL, db, NULL);
				ret = false;
			} else {
				// If pass is sent with 'COM_CHANGE_USER', we proceed trying to use
				// it to authenticate the user. See #3504 for more context.
				ret = verify_user_pass(
					session_type, password, reinterpret_cast<char*>(user), reinterpret_cast<char*>(pass),
					pass_len, static_cast<char*>(account_details.sha1_pass), client_auth_plugin
				);
			}
		}
	}
	if (userinfo->username) free(userinfo->username);
	if (userinfo->password) free(userinfo->password);
	if (ret==true) {
		(*myds)->DSS=STATE_CLIENT_HANDSHAKE;

		userinfo->username=strdup((const char *)user);
		userinfo->password=strdup((const char *)password);
		if (db) userinfo->set_schemaname(db,strlen(db));
	} else {
		// we always duplicate username and password, or crashes happen
		userinfo->username=strdup((const char *)user);
		userinfo->password=strdup((const char *)"");
	}
	if (password) {
		free(password);
		password=NULL;
	}
	free_account_details(account_details);
	userinfo->set(NULL,NULL,NULL,NULL); // just to call compute_hash()
	if (ret) {
		// we need to process charset if present in CHANGE_USER
		uint16_t charset=0;
		int bytes_processed = (db-(char *)pkt);
		bytes_processed += strlen(db) + 1;
		int bytes_left = len - bytes_processed;
		if (bytes_left > 2) {
			char *p = db;
			p += strlen(db);
			p++; // null byte
			memcpy(&charset, p, sizeof(charset));
		}
		// see bug #810
		if (charset==0) {
			const MARIADB_CHARSET_INFO *ci = NULL;
			ci = proxysql_find_charset_name(mysql_thread___default_variables[SQL_CHARACTER_SET]);
			if (!ci) {
				// LCOV_EXCL_START
				proxy_error("Cannot find charset [%s]\n", mysql_thread___default_variables[SQL_CHARACTER_SET]);
				assert(0);
				// LCOV_EXCL_STOP
			}
			charset=ci->nr;
		}
		// reject connections from unknown charsets
		const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(charset);
		if (!c) {
			proxy_error("Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds)->addr.addr, (*myds)->addr.port, charset);
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds), (*myds)->sess, user, (*myds)->addr.addr, (*myds)->addr.port, charset);
			ret = false;
			return ret;
		}
		// set the default charset for this session
		(*myds)->sess->default_charset = charset;
		if ((*myds)->sess->user_attributes) {
			if (user_attributes_has_spiffe(__LINE__, __func__, user)) {
				// if SPIFFE was used, CHANGE_USER is not allowed.
				// This because when SPIFFE is used, the password it is not relevant,
				// as it could be a simple "none" , or "123456", or "password"
				// The whole idea of using SPIFFE is that this is responsible for
				// authentication, and not the password.
				// Therefore CHANGE_USER is not allowed
				proxy_error("Client %s:%d is trying to run CHANGE_USER , but this is disabled because it previously used SPIFFE ID. Disconnecting\n", (*myds)->addr.addr, (*myds)->addr.port);
				ret = false;
				return ret;
			}

			char* user_attributes = (*myds)->sess->user_attributes;
			if (strlen(user_attributes)) {
				nlohmann::json j_user_attributes = nlohmann::json::parse(user_attributes);
				auto default_transaction_isolation = j_user_attributes.find("default-transaction_isolation");

				if (default_transaction_isolation != j_user_attributes.end()) {
					std::string def_trx_isolation_val =
						j_user_attributes["default-transaction_isolation"].get<std::string>();
					mysql_variables.client_set_value((*myds)->sess, SQL_ISOLATION_LEVEL, def_trx_isolation_val.c_str());
				}
			}
		}
		assert(sess);
		assert(sess->client_myds);
		MySQL_Connection *myconn=sess->client_myds->myconn;
		assert(myconn);

		myconn->set_charset(charset, CONNECT_START);

		std::stringstream ss;
		ss << charset;

		/* We are processing handshake from client. Client sends us a character set it will use in communication.
		 * we store this character set in the client's variables to use later in multiplexing with different backends
		 */
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_RESULTS, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CLIENT, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CONNECTION, ss.str().c_str());
		mysql_variables.client_set_value(sess, SQL_COLLATION_CONNECTION, ss.str().c_str());
	}
	return ret;
}

// this function was inline in process_pkt_handshake_response() , split for readibility
int MySQL_Protocol::PPHR_1(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) { // process_pkt_handshake_response inner 1
	if ((*myds)->switching_auth_stage == 1) {
		// this was set in PPHR_4auth0() or PPHR_4auth1()
		(*myds)->switching_auth_stage=2;
	}
	if ((*myds)->switching_auth_stage == 4) {
		// this was set in PPHR_sha2full()
		(*myds)->switching_auth_stage=5;
	}
	(*myds)->auth_in_progress = 0;
	if (len==5) {
		ret = false;
		vars1.user = (unsigned char *)(*myds)->myconn->userinfo->username;
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client is disconnecting\n", (*myds), (*myds)->sess, vars1.user);
		proxy_error("User '%s'@'%s' is disconnecting during switch auth\n", vars1.user, (*myds)->addr.addr);
		(*myds)->auth_in_progress = 0;
		return 1;
	}
	auth_plugin_id = (*myds)->switching_auth_type;
	if (auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) {
		vars1.pass_len = len - sizeof(mysql_hdr);
	} else {
		vars1.pass_len=strlen((char *)pkt);
	}
	vars1.pass = (unsigned char *)malloc(vars1.pass_len+1);
	memcpy(vars1.pass, pkt, vars1.pass_len);
	vars1.pass[vars1.pass_len] = 0;
	vars1.user = (unsigned char *)(*myds)->myconn->userinfo->username;
	vars1.db = (*myds)->myconn->userinfo->schemaname;
	//(*myds)->switching_auth_stage=2;
	vars1.charset=(*myds)->tmp_charset;
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,2,"Session=%p , DS=%p . Encrypted: %d , switching_auth: %d, auth_plugin_id: %d\n", (*myds)->sess, (*myds), (*myds)->encrypted, (*myds)->switching_auth_stage, auth_plugin_id);
	vars1.capabilities = (*myds)->myconn->options.client_flag;
	return 2;
}

// this function was inline in process_pkt_handshake_response() , split for readibility
bool MySQL_Protocol::PPHR_2(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) { // process_pkt_handshake_response inner 2
	vars1.capabilities = CPY4(pkt);
	// see bug #2916. If CLIENT_MULTI_STATEMENTS is set by the client
	// we enforce setting CLIENT_MULTI_RESULTS, this is the proper and expected
	// behavior (refer to 'https://dev.mysql.com/doc/c-api/8.0/en/c-api-multiple-queries.html').
	// Don't enforcing this would cause a mismatch between client and backend
	// connections flags.
	if (vars1.capabilities & CLIENT_MULTI_STATEMENTS) {
		vars1.capabilities |= CLIENT_MULTI_RESULTS;
	}
	// we enforce disabling 'CLIENT_DEPRECATE_EOF' from the supported capabilities
	// in case it's explicitly disabled by global variable 'mysql_thread___enable_client_deprecate_eof'.
	// This is because further checks to actually threat the connection as a connection
	// supporting 'CLIENT_DEPRECATE_EOF' rely in 'client_flag' field from
	// 'MySQL_Connection::options'.
	// This is the second step for ensuring that the connection is being handling
	// in both ProxySQL and client side as a connection without 'CLIENT_DEPRECATE_EOF' support.
	// First step is replying to client during initial handshake (in 'generate_pkt_initial_handshake')
	// specifying no 'CLIENT_DEPRECATE_EOF' support in 'server_capabilities'.
	if (!mysql_thread___enable_client_deprecate_eof) {
		vars1.capabilities &= ~CLIENT_DEPRECATE_EOF;
	}
	(*myds)->myconn->options.client_flag = vars1.capabilities;
	pkt += sizeof(uint32_t);
	vars1.max_pkt = CPY4(pkt);
	(*myds)->myconn->options.max_allowed_pkt = vars1.max_pkt;
	pkt += sizeof(uint32_t);
	vars1.charset = *(uint8_t *)pkt;
	if ( (*myds)->encrypted == false ) { // client wants to use SSL
		if (len == sizeof(mysql_hdr)+32) {
			(*myds)->encrypted = true;
			vars1.use_ssl = true;
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
	}
	// see bug #810
	if (vars1.charset==0) {
		const MARIADB_CHARSET_INFO *ci = NULL;
		ci = proxysql_find_charset_name(mysql_thread___default_variables[SQL_CHARACTER_SET]);
		if (!ci) {
			// LCOV_EXCL_START
			proxy_error("Cannot find charset [%s]\n", mysql_thread___default_variables[SQL_CHARACTER_SET]);
			assert(0);
			// LCOV_EXCL_STOP
		}
		vars1.charset=ci->nr;
	}
	(*myds)->tmp_charset = vars1.charset;
	pkt += 24;
//	if (len==sizeof(mysql_hdr)+32) {
//		(*myds)->encrypted=true;
//		use_ssl=true;
//	} else {
	vars1.user = pkt;
	pkt += strlen((char *)vars1.user) + 1;

	if (vars1.capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
		uint64_t passlen64;
		int pass_len_enc=mysql_decode_length(pkt,&passlen64);
		vars1.pass_len = passlen64;
		pkt	+= pass_len_enc;
		if (vars1.pass_len > (len - (pkt - vars1._ptr))) {
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
	} else {
		vars1.pass_len = (vars1.capabilities & CLIENT_SECURE_CONNECTION ? *pkt++ : strlen((char *)pkt));
		if (vars1.pass_len > (len - (pkt - vars1._ptr))) {
			ret = false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response\n", (*myds), (*myds)->sess, vars1.user);
			return false;
		}
	}
	vars1.pass = (unsigned char *)malloc(vars1.pass_len+1);
	memcpy(vars1.pass, pkt, vars1.pass_len);
	vars1.pass[vars1.pass_len] = 0;

	pkt += vars1.pass_len;
	if (vars1.capabilities & CLIENT_CONNECT_WITH_DB) {
		unsigned int remaining = len - (pkt - vars1._ptr);
		vars1.db_tmp = strndup((const char *)pkt, remaining);
		if (vars1.db_tmp) {
			vars1.db = vars1.db_tmp;
		}
		pkt++;
		if (vars1.db) {
			pkt+=strlen(vars1.db);
		}
	} else {
		vars1.db = NULL;
	}
	if (vars1.pass_len) {
		if (vars1.pass[vars1.pass_len-1] == 0) {
			vars1.pass_len--; // remove the extra 0 if present
		}
	}
	if (vars1._ptr+len > pkt) {
		if (vars1.capabilities & CLIENT_PLUGIN_AUTH) {
			vars1.auth_plugin = pkt;
		}
	}
	return true;
}

void MySQL_Protocol::PPHR_3(MyProt_tmp_auth_vars& vars1) { // detect plugin id
	if (vars1.auth_plugin == NULL) {
		vars1.auth_plugin = (unsigned char *)"mysql_native_password"; // default
		auth_plugin_id = AUTH_MYSQL_NATIVE_PASSWORD;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_plugin_id=%d\n", (*myds), (*myds)->sess, vars1.user, auth_plugin_id);

	if (auth_plugin_id == AUTH_UNKNOWN_PLUGIN) {
		if (strncmp((char *)vars1.auth_plugin,plugins[0],strlen(plugins[0]))==0) { // mysql_native_password
			auth_plugin_id = AUTH_MYSQL_NATIVE_PASSWORD;
		} else if (strncmp((char *)vars1.auth_plugin,plugins[1],strlen(plugins[1]))==0) { // mysql_clear_password
			auth_plugin_id = AUTH_MYSQL_CLEAR_PASSWORD;
		} else if (strncmp((char *)vars1.auth_plugin,plugins[2],strlen(plugins[2]))==0) { // caching_sha2_password
			if (sent_auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) {
				// if we send mysql_native_password as default authentication plugin we do not support
				// clients using caching_sha2_password , thus we define "unknown plugin" and force the
				// client to switch to mysql_native_password
				auth_plugin_id = AUTH_UNKNOWN_PLUGIN;
			} else if (sent_auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
				auth_plugin_id = AUTH_MYSQL_CACHING_SHA2_PASSWORD;
			} else {
				assert(0);
			}
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_plugin_id=%d\n", (*myds), (*myds)->sess, vars1.user, auth_plugin_id);
}

bool MySQL_Protocol::PPHR_4auth0(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) {
	if ((*myds)->switching_auth_stage == 0) {
		(*myds)->switching_auth_stage = 1;
		(*myds)->auth_in_progress = 1;
		// check if user exists
		bool user_exists = true;
		if (GloMyLdapAuth) { // we check if user exists only if GloMyLdapAuth is enabled
#ifdef PROXYSQLCLICKHOUSE
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
				//user_exists = GloClickHouseAuth->exists((char *)user);
				// for clickhouse, we currently do not support clear text or LDAP
				user_exists = true;
			} else {
#endif /* PROXYSQLCLICKHOUSE */
				user_exists = GloMyAuth->exists((char *)vars1.user);
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user_exists=%d , user='%s'\n", (*myds), (*myds)->sess, user_exists, vars1.user);
#ifdef PROXYSQLCLICKHOUSE
			}
#endif /* PROXYSQLCLICKHOUSE */
		}
		if (user_exists) {
			(*myds)->switching_auth_type = AUTH_MYSQL_NATIVE_PASSWORD; // mysql_native_password
		} else {
			(*myds)->switching_auth_type = AUTH_MYSQL_CLEAR_PASSWORD; // mysql_clear_password
		}
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user_exists=%d , user='%s' , setting switching_auth_type=%d\n", (*myds), (*myds)->sess, user_exists, vars1.user, (*myds)->switching_auth_type);
		generate_pkt_auth_switch_request(true, NULL, NULL);
		(*myds)->myconn->userinfo->set((char *)vars1.user, NULL, vars1.db, NULL);
		ret = false;
		return false;
	}
	return true;
}


bool MySQL_Protocol::PPHR_4auth1(unsigned char *pkt, unsigned int len, bool& ret, MyProt_tmp_auth_vars& vars1) {
	if (GloMyLdapAuth) {
		if ((*myds)->switching_auth_stage == 0) {
			bool user_exists = true;
#ifdef PROXYSQLCLICKHOUSE
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
				//user_exists = GloClickHouseAuth->exists((char *)user);
				// for clickhouse, we currently do not support clear text or LDAP
				user_exists = true;
			} else {
#endif /* PROXYSQLCLICKHOUSE */
				user_exists = GloMyAuth->exists((char *)vars1.user);
#ifdef PROXYSQLCLICKHOUSE
			}
#endif /* PROXYSQLCLICKHOUSE */
			if (user_exists == false) {
				(*myds)->switching_auth_type = AUTH_MYSQL_CLEAR_PASSWORD; // mysql_clear_password
				(*myds)->switching_auth_stage = 1;
				(*myds)->auth_in_progress = 1;
				generate_pkt_auth_switch_request(true, NULL, NULL);
				(*myds)->myconn->userinfo->set((char *)vars1.user, NULL, vars1.db, NULL);
				ret = false;
				proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . goto __exit_process_pkt_handshake_response. User does not exist\n", (*myds), (*myds)->sess, vars1.user);
				return false;
			}
		}
	}
	return true;
}

void MySQL_Protocol::PPHR_5passwordTrue(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
#ifdef DEBUG
	proxy_debug(
		PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password='%s'\n",
		(*myds), (*myds)->sess, vars1.user, mf_unique_ptr<const char>(get_masked_pass(vars1.password)).get()
	);
#endif // debug
	// Could be reached several times before auth completion; allocating attributes should be reset
	(*myds)->sess->default_hostgroup = attr1.default_hostgroup;
	// Protect against multiple calls; only replace on property change
	if ((*myds)->sess->default_schema && ((*myds)->sess->default_schema != attr1.default_schema)) {
		free((*myds)->sess->default_schema);
		(*myds)->sess->default_schema = nullptr;
	}
	// TODO: Not ideal, but the flow is currently too complex. Simplifying resource management so
	// we can reduce extra alloctions should be part of the next rework.
	(*myds)->sess->default_schema = attr1.default_schema ? strdup(attr1.default_schema) : nullptr;
	// Protect against multiple calls; only replace on property change
	if ((*myds)->sess->user_attributes && (*myds)->sess->user_attributes != attr1.attributes) {
		free((*myds)->sess->user_attributes);
		(*myds)->sess->user_attributes = nullptr;
	}
	// TODO: Not ideal, but the flow is currently too complex. Simplifying resource management so
	// we can reduce extra alloctions should be part of the next rework.
	(*myds)->sess->user_attributes = attr1.attributes ? strdup(attr1.attributes) : nullptr;
#ifdef DEBUG
	debug_spiffe_id(vars1.user,attr1.attributes, __LINE__, __func__);
#endif
	(*myds)->sess->schema_locked = attr1.schema_locked;
	(*myds)->sess->transaction_persistent = attr1.transaction_persistent;
	(*myds)->sess->session_fast_forward=false; // default
	if ((*myds)->sess->session_type == PROXYSQL_SESSION_MYSQL) {
		(*myds)->sess->session_fast_forward = attr1.fast_forward;
	}
	(*myds)->sess->user_max_connections = attr1.max_connections;
}


void MySQL_Protocol::PPHR_5passwordFalse_0(
	// FIXME: does this work only for mysql_native_password ?
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1) {
	if (strcmp((const char *)vars1.user,mysql_thread___monitor_username)==0) {
		proxy_scramble(reply, (*myds)->myconn->scramble_buff, mysql_thread___monitor_password);
		if (memcmp(reply, vars1.pass, SHA_DIGEST_LENGTH)==0) {
			(*myds)->sess->default_hostgroup=STATS_HOSTGROUP;
			(*myds)->sess->default_schema=strdup((char *)"main"); // just the pointer is passed
			(*myds)->sess->schema_locked=false;
			(*myds)->sess->transaction_persistent=false;
			(*myds)->sess->session_fast_forward=false;
			(*myds)->sess->user_max_connections=0;
			vars1.password=l_strdup(mysql_thread___monitor_password);
			ret=true;
		}
	} else {
		ret=false;
	}
}

void MySQL_Protocol::PPHR_5passwordFalse_auth2(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
	if (GloMyLdapAuth) {
#ifdef DEBUG
		{
			char *tmp_pass=strdup((const char *)vars1.pass);
			int lpass = strlen(tmp_pass);
			for (int i=2; i<lpass-1; i++) {
				tmp_pass[i]='*';
			}
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password='%s'\n", (*myds), (*myds)->sess, vars1.user, tmp_pass);
			free(tmp_pass);
		}
#endif // debug
		char *backend_username = NULL;
		(*myds)->sess->use_ldap_auth = true;
		vars1.password = GloMyLdapAuth->lookup((char *) vars1.user, (char *) vars1.pass, USERNAME_FRONTEND, 
			&attr1.use_ssl, &attr1.default_hostgroup, &attr1.default_schema, &attr1.schema_locked,
			&attr1.transaction_persistent, &attr1.fast_forward, &attr1.max_connections, &attr1.sha1_pass, &attr1.attributes, &backend_username);
		if (vars1.password) {
#ifdef DEBUG
			char *tmp_pass=strdup(vars1.password);
			int lpass = strlen(tmp_pass);
			for (int i=2; i<lpass-1; i++) {
				tmp_pass[i]='*';
			}
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password='%s'\n", (*myds), (*myds)->sess, backend_username, tmp_pass);
			free(tmp_pass);
#endif // debug
			(*myds)->sess->default_hostgroup=attr1.default_hostgroup;
			(*myds)->sess->default_schema=attr1.default_schema; // just the pointer is passed
			(*myds)->sess->user_attributes = attr1.attributes; // just the pointer is passed, LDAP returns empty string
#ifdef DEBUG
			debug_spiffe_id(vars1.user,attr1.attributes, __LINE__, __func__);
#endif
			(*myds)->sess->schema_locked=attr1.schema_locked;
			(*myds)->sess->transaction_persistent=attr1.transaction_persistent;
			(*myds)->sess->session_fast_forward=attr1.fast_forward;
			(*myds)->sess->user_max_connections=attr1.max_connections;
			if (strcmp(vars1.password, (char *) vars1.pass) == 0) {
				if (backend_username) {
					account_details_t acct {
						GloMyAuth->lookup(backend_username, USERNAME_BACKEND, { true, true, true })
					};

					if (acct.password) {
						(*myds)->sess->default_hostgroup=attr1.default_hostgroup;
						// Free the previously set 'default_schema' by 'GloMyLdapAuth'
						if ((*myds)->sess->default_schema) {
							free((*myds)->sess->default_schema);
						}
						(*myds)->sess->default_schema=attr1.default_schema; // just the pointer is passed
						// Free the previously set 'user_attributes' by 'GloMyLdapAuth'
						if ((*myds)->sess->user_attributes) {
							free((*myds)->sess->user_attributes);
						}
						(*myds)->sess->user_attributes = attr1.attributes; // just the pointer is passed
#ifdef DEBUG
						proxy_info("Attributes for user %s: %s\n" , acct.username, attr1.attributes);
#endif
						(*myds)->sess->schema_locked=attr1.schema_locked;
						(*myds)->sess->transaction_persistent=attr1.transaction_persistent;
						(*myds)->sess->session_fast_forward=attr1.fast_forward;
						(*myds)->sess->user_max_connections=attr1.max_connections;
						char *tmp_user=strdup((const char *)acct.username);
						userinfo->set(backend_username, NULL, NULL, NULL);
						// 'MySQL_Connection_userinfo::set' duplicates the supplied information, 'free' is required.
						free(backend_username);
						if (attr1.sha1_pass==NULL) {
							// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
							// TODO: CHECK these usages of 'reply'
							GloMyAuth->set_SHA1((char *)userinfo->username, USERNAME_FRONTEND,reply);
						}
						if (userinfo->sha1_pass) free(userinfo->sha1_pass);
						userinfo->sha1_pass=sha1_pass_hex(reply);
						userinfo->fe_username=strdup((const char *)tmp_user);
						free(tmp_user);
						ret=true;
					} else {
						proxy_error("Unable to load credentials for backend user %s , associated to LDAP user %s\n", backend_username, acct.username);
					}

					free_account_details(acct);
				} else {
					proxy_error("Unable to find backend user associated to LDAP user '%s'\n", vars1.user);
					ret=false;
				}
			}
		}
	}
}

void MySQL_Protocol::PPHR_6auth2(
	bool& ret,
	MyProt_tmp_auth_vars& vars1
	) {
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
		unsigned char a[SHA256_DIGEST_LENGTH];
		unsigned char b[SHA256_DIGEST_LENGTH];
		unsigned char c[SHA256_DIGEST_LENGTH+20];
		unsigned char d[SHA256_DIGEST_LENGTH];
		unsigned char e[SHA256_DIGEST_LENGTH];
		SHA256((const unsigned char *)vars1.password, strlen(vars1.password), a);
		SHA256(a, SHA256_DIGEST_LENGTH, b);
		memcpy(c,b,SHA256_DIGEST_LENGTH);
		memcpy(c+SHA256_DIGEST_LENGTH, (*myds)->myconn->scramble_buff, 20);
		SHA256(c, SHA256_DIGEST_LENGTH+20, d);
		for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
			e[i] = a[i] ^ d[i];
		}
		if (memcmp(e,vars1.pass,SHA256_DIGEST_LENGTH)==0) {
			ret = true;
		}
	}
}

void MySQL_Protocol::PPHR_7auth1(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
		ret=proxy_scramble_sha1((char *)vars1.pass,(*myds)->myconn->scramble_buff,vars1.password+1, reply);
		if (ret) {
			if (attr1.sha1_pass==NULL) {
				// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
				GloMyAuth->set_SHA1((char *)vars1.user, USERNAME_FRONTEND,reply);
			}
			if (userinfo->sha1_pass)
				free(userinfo->sha1_pass);
			userinfo->sha1_pass=sha1_pass_hex(reply);
		}
	}
}


void MySQL_Protocol::PPHR_7auth2(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	char * reply,
	account_details_t& attr1
) {
	enum proxysql_session_type session_type = (*myds)->sess->session_type;
	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , session_type=%d\n", (*myds), (*myds)->sess, vars1.user, session_type);
/*
		uint8_t hash_stage1[SHA_DIGEST_LENGTH];
		uint8_t hash_stage2[SHA_DIGEST_LENGTH];
		SHA_CTX sha1_context;
		SHA1_Init(&sha1_context);
		SHA1_Update(&sha1_context, vars1.pass, vars1.pass_len);
		SHA1_Final(hash_stage1, &sha1_context);
		SHA1_Init(&sha1_context);
		SHA1_Update(&sha1_context,hash_stage1,SHA_DIGEST_LENGTH);
		SHA1_Final(hash_stage2, &sha1_context);
		char *double_hashed_password = sha1_pass_hex((char *)hash_stage2); // note that sha1_pass_hex() returns a new buffer
*/
		unsigned char md1_buf[SHA_DIGEST_LENGTH];
		unsigned char md2_buf[SHA_DIGEST_LENGTH];
		SHA1(vars1.pass, vars1.pass_len, md1_buf);
		SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
		char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer

		if (strcasecmp(double_hashed_password,vars1.password)==0) {
			ret = true;
			if (attr1.sha1_pass==NULL) {
				// currently proxysql doesn't know any sha1_pass for that specific user, let's set it!
				GloMyAuth->set_SHA1((char *)vars1.user, USERNAME_FRONTEND,md1_buf);
			}
			if (userinfo->sha1_pass)
				free(userinfo->sha1_pass);
			userinfo->sha1_pass=sha1_pass_hex((char *)md1_buf);
		} else {
			ret = false;
		}
		free(double_hashed_password);
	}
}

bool MySQL_Protocol::PPHR_verify_sha2(
	MyProt_tmp_auth_vars& vars1,
	enum proxysql_auth_plugins passformat,
	PASSWORD_TYPE::E passtype
) {
	bool ret = false;

	if ((*myds)->switching_auth_stage == 5) {
		if (passformat == AUTH_MYSQL_NATIVE_PASSWORD) {
			unsigned char md1_buf[SHA_DIGEST_LENGTH];
			unsigned char md2_buf[SHA_DIGEST_LENGTH];
			SHA1(vars1.pass, vars1.pass_len, md1_buf);
			SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
			char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer
			if (strcasecmp(double_hashed_password,vars1.password)==0) {
				ret = true;
			}
			free(double_hashed_password);
		} else if (passformat == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
			assert(strlen(vars1.password) == 70);
			string sp = string(vars1.password);
			long rounds = stol(sp.substr(3,3));
			string salt = sp.substr(7,20);
			string sha256hash = sp.substr(27,43);
			char buf[100];
			salt = "$5$rounds=" + to_string(rounds*1000) + "$" + salt;
			sha256_crypt_r((const char*)vars1.pass, salt.c_str(), buf, sizeof(buf));
			string sbuf = string(buf);
			std::size_t found = sbuf.find_last_of("$");
			assert(found != string::npos);
			sbuf = sbuf.substr(found+1);
			if (strcmp(sbuf.c_str(),vars1.password+27)==0) {
				ret = true;
			}
		} else {
			// Programatic error; invalid param
			assert(0);
		}
	}

	return ret;
}

void MySQL_Protocol::PPHR_sha2full(
	bool& ret,
	MyProt_tmp_auth_vars& vars1,
	enum proxysql_auth_plugins passformat,
	PASSWORD_TYPE::E passtype
) {
	if ((*myds)->switching_auth_stage == 0) {
		const unsigned char perform_full_authentication = '\4';
		generate_one_byte_pkt(perform_full_authentication);
		// Required to be set; later used in 'PPHR_1' for setting current 'auth_plugin_id'. E.g:
		//  - mysql-default_authentication_plugin: 'caching_sha2_password'
		//  - Requested authentication: 'caching_sha2_password'
		//  - Stored password: 'mysql_native_password'
		// A full auth is required; and the switching auth type will be used later in 'PPHR_1'.
		(*myds)->switching_auth_type = auth_plugin_id;
		(*myds)->switching_auth_stage = 4;
		(*myds)->auth_in_progress = 1;
	} else if ((*myds)->switching_auth_stage == 5) {
		if (passformat == AUTH_MYSQL_NATIVE_PASSWORD) {
			unsigned char md1_buf[SHA_DIGEST_LENGTH];
			unsigned char md2_buf[SHA_DIGEST_LENGTH];
			SHA1(vars1.pass, vars1.pass_len, md1_buf);
			SHA1(md1_buf,SHA_DIGEST_LENGTH,md2_buf);
			char *double_hashed_password = sha1_pass_hex((char *)md2_buf); // note that sha1_pass_hex() returns a new buffer
			if (strcasecmp(double_hashed_password,vars1.password)==0) {
				ret = true;
			}
			free(double_hashed_password);
		} else if (passformat == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
			assert(strlen(vars1.password) == 70);
			string sp = string(vars1.password);
			long rounds = stol(sp.substr(3,3));
			string salt = sp.substr(7,20);
			string sha256hash = sp.substr(27,43);
			//char * sha256_crypt_r (const char *key, const char *salt, char *buffer, int buflen);
			char buf[100];
			salt = "$5$rounds=" + to_string(rounds*1000) + "$" + salt;
			sha256_crypt_r((const char*)vars1.pass, salt.c_str(), buf, sizeof(buf));
			string sbuf = string(buf);
			std::size_t found = sbuf.find_last_of("$");
			assert(found != string::npos);
			sbuf = sbuf.substr(found+1);
			if (strcmp(sbuf.c_str(),vars1.password+27)==0) {
				ret = true;
			}
		} else {
			assert(0);
		}
		if (ret == true) {
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE || session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
				// currently proxysql doesn't know the clear text password for that specific user, let's set it!
				GloMyAuth->set_clear_text_password((char *)vars1.user, USERNAME_FRONTEND, (const char *)vars1.pass, passtype);
				// Update 'vars1' password with 'clear text' one, so session can be later updated with it
				if (vars1.password) { free(vars1.password); }
				vars1.password = strdup(reinterpret_cast<const char*>(vars1.pass));
			}
		}
	} else {
		assert(0);
	}
}

void MySQL_Protocol::PPHR_SetConnAttrs(MyProt_tmp_auth_vars& vars1, account_details_t& attr1) {
	MySQL_Connection *myconn = NULL;
	myconn=sess->client_myds->myconn;
	assert(myconn);
	myconn->set_charset(vars1.charset, CONNECT_START);

	std::stringstream ss;
	ss << vars1.charset;

	/* We are processing handshake from client. Client sends us a character set it will use in communication.
	 * we store this character set in the client's variables to use later in multiplexing with different backends
	 */
	mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_RESULTS, ss.str().c_str());
	mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CLIENT, ss.str().c_str());
	mysql_variables.client_set_value(sess, SQL_CHARACTER_SET_CONNECTION, ss.str().c_str());
	mysql_variables.client_set_value(sess, SQL_COLLATION_CONNECTION, ss.str().c_str());

	// enable compression
	if (vars1.capabilities & CLIENT_COMPRESS) {
		if (myconn->options.server_capabilities & CLIENT_COMPRESS) {
			myconn->options.compression_min_length=50;
			//myconn->set_status_compression(true);  // don't enable this here. It needs to be enabled after the OK is sent
		}
	}
	if (attr1.use_ssl==true) {
		(*myds)->sess->use_ssl = true;
	}
}

// PPHR_proc_auth_stage :: bool -> MySQL_Protocol::MySQL_Data_Stream -> auth_plugin_id -> OSC
// PPHR_cont_auth :: bool -> MySQL_Protocol::MySQL_Data_Stream -> auth_plugin_id -> OSC
// MySQL_Protocol::verify_password :: vars1 -> account_details_t -> bool
// Template idea for auth in stages; not used at the moment
/*
void MySQL_Protocol::PPHR_next_auth_stage(MyProt_tmp_auth_vars& vars1, PASSWORD_TYPE::E passtype) {
	if (
		auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD
		&&
		strlen(vars1.password) == 70
		&&
		strncasecmp(vars1.password, "$A$0", 4) == 0
	) {
		if ((*myds)->switching_auth_stage == 0) {
			const unsigned char perform_full_authentication = '\4';
			generate_one_byte_pkt(perform_full_authentication);
			(*myds)->switching_auth_type = auth_plugin_id;
			(*myds)->switching_auth_stage = 4;
			(*myds)->auth_in_progress = 1;
		} else if ((*myds)->switching_auth_stage == 5) {
			enum proxysql_session_type session_type = (*myds)->sess->session_type;
			if (
				session_type == PROXYSQL_SESSION_MYSQL ||
				session_type == PROXYSQL_SESSION_SQLITE ||
				session_type == PROXYSQL_SESSION_ADMIN ||
				session_type == PROXYSQL_SESSION_STATS
			) {
				// Clear text password currently unknown for that specific user; let's set it!
				GloMyAuth->set_clear_text_password(
					(char *)vars1.user, USERNAME_FRONTEND, (const char *)vars1.pass, passtype
				);
				// Update 'vars1' password with 'clear text' one, so session can be later updated with it
				if (vars1.password) { free(vars1.password); }
				vars1.password = strdup(reinterpret_cast<const char*>(vars1.pass));
			}
		}
	} else if (vars1.password[0] != '*') {
		if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD && (*myds)->switching_auth_stage == 0) {
		}
	} else {
	}
}
*/

//
// Update global state if pass verified:
// - If auth finished:
//     + Save password: sha1 || clear_text_password
// - If not (caching_sha2_password):
//     + Continue auth; trigger contitue of full auth
bool MySQL_Protocol::PPHR_verify_password(MyProt_tmp_auth_vars& vars1, account_details_t& account_details) {
	bool ret = false;
	char reply[SHA_DIGEST_LENGTH + 1] = { 0 };

	if (vars1.password == NULL) {
		// this is a workaround for bug #603
		if (
			((*myds)->sess->session_type == PROXYSQL_SESSION_ADMIN)
			||
			((*myds)->sess->session_type == PROXYSQL_SESSION_STATS)
			||
			((*myds)->sess->session_type == PROXYSQL_SESSION_SQLITE)
		) {
			PPHR_5passwordFalse_0(ret, vars1, reply, account_details);
		} else {
			// assume failure
			ret=false;
			// try LDAP
			if (auth_plugin_id == AUTH_MYSQL_CLEAR_PASSWORD) {
				PPHR_5passwordFalse_auth2(ret, vars1, reply, account_details);
			}
		}
	} else {
		// update 'MySQL_Session' info using 'account_details'; transfers ownership of:
		//  - 'ad::default_schema', 'ad::attributes'
		PPHR_5passwordTrue(ret, vars1, reply, account_details);

		if (vars1.pass_len==0 && strlen(vars1.password)==0) {
			ret=true;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password=''\n", (*myds), (*myds)->sess, vars1.user);
		}
		// For empty passwords client expects either 'OK' or 'ERR'
		else if (vars1.pass_len == 0 && strlen(vars1.password) != 0) {
			ret=false;
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password=''\n", (*myds), (*myds)->sess, vars1.user);
		}
		else {
#ifdef DEBUG
			proxy_debug(
				PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , username='%s' , password='%s' , auth_plugin_id=%d\n",
				(*myds), (*myds)->sess, vars1.user, get_masked_pass(vars1.password).get(), auth_plugin_id
			);
#endif // debug
			if (
				auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD
				&&
				strlen(vars1.password) == 70
				&&
				strncasecmp(vars1.password,"$A$0",4)==0
			) {
				// We have a hashed caching_sha2_password
				PPHR_sha2full(ret, vars1, AUTH_MYSQL_CACHING_SHA2_PASSWORD, vars1.passtype);
			} else if (vars1.password[0]!='*') { // clear text password
				if (auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) { // mysql_native_password
					proxy_scramble(reply, (*myds)->myconn->scramble_buff, vars1.password);
					if (vars1.pass_len != 0 && memcmp(reply, vars1.pass, SHA_DIGEST_LENGTH)==0) {
						ret=true;
					}
				} else if (auth_plugin_id == AUTH_MYSQL_CLEAR_PASSWORD)  { // mysql_clear_password
					if (strcmp(vars1.password, (char *) vars1.pass) == 0) {
						ret = true;
					}
				} else if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) { // caching_sha2_password
					// Checking 'switching_auth_stage' is required case due to a potential concurrent update
					// of pass in 'GloMyAuth'. When the pass found is clear-text it's assumed that full-auth
					// is never required and that we are in the first auth stage, because of this, the pass
					// received by the client is assumed to be hashed (first auth data received). Yet, during
					// during a 'full-auth' the pass stored in 'GloMyAuth' could have been updated either by
					// user action or by another concurrent connection that called 'set_clear_text_pass' on
					// completion. In this case, we would have received a 'clear-text' pass form 'GloMyAuth'
					// but we since we would be in the final auth stage, the pass sent by client should also
					// be 'clear-text' (encrypt-pass).
					if ((*myds)->switching_auth_stage == 5) {
						if (strcmp(vars1.password, reinterpret_cast<char*>(vars1.pass)) == 0) {
							ret = true;
						}
					} else {
						PPHR_6auth2(ret, vars1);
						if (ret == true) {
							if ((*myds)->switching_auth_stage == 0) {
								const unsigned char fast_auth_success = '\3';
								generate_one_byte_pkt(fast_auth_success);
							}
						}
					}
				} else {
					assert(0);
				}
			} else { // password hashed with SHA1 , mysql_native_password format
				if (auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) { // mysql_native_password
					PPHR_7auth1(ret, vars1, reply, account_details);
				} else if (auth_plugin_id == AUTH_MYSQL_CLEAR_PASSWORD) { // mysql_clear_password
					PPHR_7auth2(ret, vars1, reply, account_details);
				} else if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) { // caching_sha2_password
					PPHR_sha2full(ret, vars1, AUTH_MYSQL_NATIVE_PASSWORD, vars1.passtype);
				} else {
					assert(0);
				}
			}
		}
	}

	return ret;
}

#include <unordered_map>
#include <mutex>
#include <string>
#include <random>
std::string generateSessionIDnew() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(100000, 999999);
    return std::to_string(dist(gen));
}
std::unordered_map<std::string, std::string> session_extra_data_map;
std::string session_idp;

/**
 * @brief Process handshake response from the client, and it needs to be called until
 *   the authentication is completed (successfully or failed)
 *
 * @return:
 *      true: the authentication completed
 *      false: the authentication failed, or more data is needed
 */
bool MySQL_Protocol::process_pkt_handshake_response(unsigned char *pkt, unsigned int len) {
#ifdef DEBUG
    if (dump_pkt) { __dump_pkt(__func__, pkt, len); }
#endif

    bool ret = false;
    auth_plugin_id = AUTH_UNKNOWN_PLUGIN;

    enum proxysql_session_type session_type = (*myds)->sess->session_type;
    MyProt_tmp_auth_vars vars1;
    account_details_t account_details {};
    dup_account_details_t dup_details { true, true, true };

    vars1._ptr = pkt;
    mysql_hdr hdr;
    bool bool_rc = false;
    memcpy(&hdr, pkt, sizeof(mysql_hdr));
    pkt += sizeof(mysql_hdr);

    bool_rc = PPHR_2(pkt, len, ret, vars1);
    if (bool_rc == false)
        goto __exit_process_pkt_handshake_response;

    std::cout << "[DEBUG BEFORE] User: " << (vars1.user ? (char*)vars1.user : "NULL") << std::endl;

    if (vars1.user) {
        std::string full_username = std::string(reinterpret_cast<char*>(vars1.user));
        size_t comma_pos = full_username.find(',');

        if (comma_pos == std::string::npos || comma_pos == full_username.length() - 1) {
            std::cout << "[ERROR] Invalid username format! Expected '<username>,<extra_data>'. Closing connection.\n";
            ret = false;  // Reject authentication
            goto __exit_process_pkt_handshake_response;
        }

        // Extract the username and extra data
        std::string clean_user = full_username.substr(0, comma_pos);
        std::string extra_data = full_username.substr(comma_pos + 1);

        // Generate a session ID
        session_idp = generateSessionIDnew();
        {
            session_extra_data_map[clean_user + "_" + session_idp] = extra_data;
        }

        // Modify the original packet (pkt) directly
        strncpy(reinterpret_cast<char*>(vars1.user), clean_user.c_str(), clean_user.length());
        vars1.user[clean_user.length()] = '\0';  // Null-terminate safely

        std::cout << "[DEBUG] Updated user: " << clean_user 
                  << " Session: " << session_idp 
                  << " Extra data: " << extra_data << std::endl;
    }

    if (hdr.pkt_id == 0 && *pkt == 2) {
        ret = false;
        proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client is disconnecting\n",
                    (*myds), (*myds)->sess, vars1.user);
        goto __exit_process_pkt_handshake_response;
    }

    if ((*myds)->myconn->userinfo->username) { // authentication already started.
        int rc = PPHR_1(pkt, len, ret, vars1);
        if (rc == 1)
            goto __exit_process_pkt_handshake_response;
        if (rc == 2)
            goto __do_auth;
        assert(0);
    }

    PPHR_3(vars1); // Detect plugin id
    proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' , auth_plugin_id=%d\n",
                (*myds), (*myds)->sess, vars1.user, auth_plugin_id);


	if (sent_auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD) {
		switch (auth_plugin_id) {
			case AUTH_UNKNOWN_PLUGIN:
				bool_rc = PPHR_4auth0(pkt, len, ret, vars1);
				if (bool_rc == false) {
					goto __exit_process_pkt_handshake_response;
				} else {
				}
				break;
			case AUTH_MYSQL_NATIVE_PASSWORD:
				bool_rc = PPHR_4auth1(pkt, len, ret, vars1);
				if (bool_rc == false) {
					goto __exit_process_pkt_handshake_response;
				} else {
				}
				break;
			case AUTH_MYSQL_CLEAR_PASSWORD:
				break;
			case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
				// this should never happen.
				// in PPHR_3 we set auth_plugin_id = AUTH_UNKNOWN_PLUGIN
				// if sent_auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD
				assert(0);
				break;
			default:
				assert(0);
				break;
		}
	} else if (sent_auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD) {
		switch (auth_plugin_id) {
			case AUTH_UNKNOWN_PLUGIN:
			case AUTH_MYSQL_NATIVE_PASSWORD:
				// for now we always switch to mysql_native_password
				// FIXME: verify if it is correct to call this here.
				// maybe it should only be called for AUTH_UNKNOWN_PLUGIN and not for AUTH_MYSQL_NATIVE_PASSWORD
				bool_rc = PPHR_4auth0(pkt, len, ret, vars1);
				if (bool_rc == false) {
					goto __exit_process_pkt_handshake_response;
				} else {
				}
				break;
			case AUTH_MYSQL_CLEAR_PASSWORD:
				break;
			case AUTH_MYSQL_CACHING_SHA2_PASSWORD:
				if ((*myds)->auth_in_progress != 0) {
					assert(0);
				}
				if ((*myds)->switching_auth_stage != 0) {
					assert(0);
				}
				break;
			default:
				break;
		}
	} else {
		assert(0);
	}

__do_auth:
	{
		// reject connections from unknown charsets
		const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(vars1.charset);
		if (!c) {
			proxy_error("Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds)->addr.addr, (*myds)->addr.port, vars1.charset);
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Client %s:%d is trying to use unknown charset %u. Disconnecting\n", (*myds), (*myds)->sess, vars1.user, (*myds)->addr.addr, (*myds)->addr.port, vars1.charset);
			ret = false;
			goto __exit_do_auth;
		}
		// set the default session charset
		(*myds)->sess->default_charset = vars1.charset;
	}
	if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
#ifdef PROXYSQLCLICKHOUSE
		ch_dup_account_details_t ch_dup_details { true, true };

		ch_account_details_t ch_account {
			GloClickHouseAuth->lookup((char*)vars1.user, USERNAME_FRONTEND, ch_dup_details)
		};

		ch_account_to_my(account_details, ch_account);
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		account_details = GloMyAuth->lookup((char*)vars1.user, USERNAME_FRONTEND, dup_details);
	}

	vars1.password = get_password(account_details, PASSWORD_TYPE::PRIMARY);
	vars1.passtype = PASSWORD_TYPE::PRIMARY;
	// the async state machine needs to change; we are creating overhead in auth for old-passwords
	ret = PPHR_verify_password(vars1, account_details);

	// full_auth have been performed an taken place, we 'may' already have clear_text of addl_pass
	if (!ret && (*myds)->auth_in_progress == 0) {
		proxy_debug(
			PROXY_DEBUG_MYSQL_AUTH, 5,
			"Attempting to use additional user password   ret='%d', switching_auht_stage='%d'\n",
			ret, (*myds)->switching_auth_stage
		);
		char* addl_pass = get_password(account_details, PASSWORD_TYPE::ADDITIONAL);

		if (addl_pass) {
			if (strlen(addl_pass) > 0) {
				if (vars1.password) { free(vars1.password); }
				vars1.password = addl_pass;
				vars1.passtype = PASSWORD_TYPE::ADDITIONAL;
				ret = PPHR_verify_password(vars1, account_details);
			} else {
				free(addl_pass);
			}
		}
	}

	if (
		ret &&
		(*myds)->auth_in_progress == 0 &&
		(*myds)->sess->session_type == PROXYSQL_SESSION_MYSQL &&
		(*myds)->sess->connections_handler == false &&
		(*myds)->sess->mirror == false
	) {
		__sync_add_and_fetch(
			vars1.passtype == PASSWORD_TYPE::PRIMARY ?
				&MyHGM->status.client_connections_prim_pass : &MyHGM->status.client_connections_addl_pass,
			1
		);
	}

__exit_do_auth:


#ifdef DEBUG
	{
		char *tmp_pass= NULL;
		if (vars1.password) {
			tmp_pass = strdup(vars1.password);
			int lpass = strlen(tmp_pass);
			for (int i=2; i<lpass-1; i++) {
				tmp_pass[i]='*';
			}
		}
		proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL,1,"Handshake (%s auth) <user:\"%s\" pass:\"%s\" db:\"%s\" max_pkt:%u>, capabilities:%u char:%u, use_ssl:%s\n",
			(vars1.capabilities & CLIENT_SECURE_CONNECTION ? "new" : "old"), vars1.user, tmp_pass, vars1.db, (*myds)->myconn->options.max_allowed_pkt, vars1.capabilities, vars1.charset, ((*myds)->encrypted ? "yes" : "no"));
		free(tmp_pass);
	}
#endif
	assert(sess);
	assert(sess->client_myds);

	// set connection attributes (charsets, compression, encryption)
	PPHR_SetConnAttrs(vars1, account_details);

#ifdef DEBUG
	if (dump_pkt) { __dump_pkt(__func__,vars1._ptr,len); }
#endif

	if (vars1.use_ssl) {
		ret=true;
		goto __exit_process_pkt_handshake_response;
	}

	// Could be reached several times before auth completion; allocating attributes should be reset
	if (ret==true) {

		(*myds)->DSS=STATE_CLIENT_HANDSHAKE;

		if (!userinfo->username) // if set already, ignore
			userinfo->username=strdup((const char *)vars1.user);
		if (userinfo->password) {
			free(userinfo->password);
		}
		userinfo->password=strdup((const char *)vars1.password);
		if (vars1.db) userinfo->set_schemaname(vars1.db,strlen(vars1.db));
		userinfo->passtype = vars1.passtype;
	} else {
		// we always duplicate username and password, or crashes happen
		if (!userinfo->username) // if set already, ignore
			userinfo->username=strdup((const char *)vars1.user);
		if (vars1.pass_len) {
			if (userinfo->password) { free(userinfo->password); }
			userinfo->password=strdup((const char *)"");
		};
		userinfo->passtype = vars1.passtype;
	}
	userinfo->set(NULL,NULL,NULL,NULL); // just to call compute_hash()

__exit_process_pkt_handshake_response:
	free(vars1.pass);
	if (vars1.password) {
		free(vars1.password);
		vars1.password=NULL;
	}
	if (vars1.db_tmp) {
		free(vars1.db_tmp);
		vars1.db_tmp=NULL;
	}
	if (ret == true) {
		ret = verify_user_attributes(__LINE__, __func__, vars1.user);
	}
	free_account_details(account_details);
	return ret;
}

bool MySQL_Protocol::verify_user_attributes(int calling_line, const char *calling_func, const unsigned char *user) {
	bool ret = true;
	if ((*myds)->sess->user_attributes) {
		char *a = (*myds)->sess->user_attributes; // no copy, just pointer
		if (strlen(a)) {
			json j = nlohmann::json::parse(a);
			auto spiffe_id = j.find("spiffe_id");
			if (spiffe_id != j.end()) {
				// at this point, we completely ignore any password specified so far
				// we assume authentication failure so far
				ret = false;
				std::string spiffe_val = j["spiffe_id"].get<std::string>();
				if ((*myds)->x509_subject_alt_name) {
					if (spiffe_val.rfind("!", 0) == 0 && spiffe_val.size() > 1) {
						string str_spiffe_regex { spiffe_val.substr(1) };
						re2::RE2::Options opts = re2::RE2::Options(RE2::Quiet);
						re2::RE2 subject_alt_regex(str_spiffe_regex, opts);

						ret = re2::RE2::FullMatch((*myds)->x509_subject_alt_name, subject_alt_regex);
					} else if (strncmp(spiffe_val.c_str(), "spiffe://", strlen("spiffe://"))==0) {
						if (strcmp(spiffe_val.c_str(), (*myds)->x509_subject_alt_name)==0) {
							ret = true;
						}
					}
				}
				if (ret == false) {
					proxy_error("%d:%s(): SPIFFE Authentication error for user %s . spiffed_id expected : %s , received: %s\n", calling_line, calling_func, user, spiffe_val.c_str(), ((*myds)->x509_subject_alt_name ? (*myds)->x509_subject_alt_name : "none"));
				}
			}
			auto default_transaction_isolation = j.find("default-transaction_isolation");
			if (default_transaction_isolation != j.end()) {
				std::string default_transaction_isolation_value = j["default-transaction_isolation"].get<std::string>();
				mysql_variables.client_set_value((*myds)->sess, SQL_ISOLATION_LEVEL, default_transaction_isolation_value.c_str());
			}
		}
	}
	return ret;
}

bool MySQL_Protocol::user_attributes_has_spiffe(int calling_line, const char *calling_func, const unsigned char *user) {
	bool ret = false;
	if ((*myds)->sess->user_attributes) {
		char *a = (*myds)->sess->user_attributes; // no copy, just pointer
		if (strlen(a)) {
			json j = nlohmann::json::parse(a);
			auto spiffe_id = j.find("spiffe_id");
			if (spiffe_id != j.end()) {
				ret = true;
			}
		}
	}
	return ret;
}

void * MySQL_Protocol::Query_String_to_packet(uint8_t sid, std::string *s, unsigned int *l) {
	mysql_hdr hdr;
	hdr.pkt_id=sid;
	hdr.pkt_length=1+s->length();
	*l=hdr.pkt_length+sizeof(mysql_hdr);
	void *pkt=malloc(*l);
	memcpy(pkt,&hdr,sizeof(mysql_hdr));
	uint8_t c=_MYSQL_COM_QUERY;
	memcpy((char *)pkt+4,&c,1);
	memcpy((char *)pkt+5,s->c_str(),s->length());
	return pkt;
}



// get_binds_from_pkt() process an STMT_EXECUTE packet, and extract binds value
// and optionally metadata
// if stmt_meta is NULL, it means it is the first time that the client run
// STMT_EXECUTE and therefore stmt_meta needs to be build
//
// returns stmt_meta, or a new one
// See https://dev.mysql.com/doc/internals/en/com-stmt-execute.html for reference
stmt_execute_metadata_t * MySQL_Protocol::get_binds_from_pkt(void *ptr, unsigned int size, MySQL_STMT_Global_info *stmt_info, stmt_execute_metadata_t **stmt_meta) {
	stmt_execute_metadata_t *ret=NULL; //return NULL in case of failure
	if (size<14) {
		// some error!
		return ret;
	}
	uint16_t num_params=stmt_info->num_params;
	if (num_params==2) {
		PROXY_TRACE();
	}
	char *p=(char *)ptr+5;
	if (*stmt_meta) { // this PS was executed at least once, and we already have metadata
		ret=*stmt_meta;
	} else { // this is the first time that this PS is executed
		ret= new stmt_execute_metadata_t();
	}
	if (*stmt_meta==NULL) {
		memcpy(&ret->stmt_id,p,4); // stmt-id
	}
	p+=4; // stmt-id
	memcpy(&ret->flags,p,1); p+=1; // flags
	p+=4; // iteration-count
	ret->num_params=num_params;
	// we keep a pointer to the packet
	// this is extremely important because:
	// * binds[X].buffer does NOT point to a new allocated buffer
	// * binds[X].buffer points to offset inside the original packet
	// FIXME: there is still no free for pkt, so that will be a memory leak that needs to be fixed
	ret->pkt=ptr;
	uint8_t new_params_bound_flag;
	if (num_params) {
		uint16_t i;
		size_t null_bitmap_length=(num_params+7)/8;
		if (size < (14+1+null_bitmap_length)) {
			// some data missing?
			delete ret;
			return NULL;
		}
		memcpy(&new_params_bound_flag,p+null_bitmap_length,1);
		uint8_t *null_bitmap=NULL;
		null_bitmap=(uint8_t *)malloc(null_bitmap_length);
		memcpy(null_bitmap,p,null_bitmap_length);
		p+=null_bitmap_length;
		p+=1; // new_params_bound_flag

		MYSQL_BIND *binds=NULL;
		my_bool *is_nulls=NULL;
		unsigned long *lengths=NULL;
		// now we create bind structures only if needed
		if (*stmt_meta==NULL) {
			binds=(MYSQL_BIND *)malloc(sizeof(MYSQL_BIND)*num_params);
			memset(binds,0,sizeof(MYSQL_BIND)*num_params);
			ret->binds=binds;
			is_nulls=(my_bool *)malloc(sizeof(my_bool)*num_params);
			ret->is_nulls=is_nulls;
			lengths=(unsigned long *)malloc(sizeof(unsigned long)*num_params);
			ret->lengths=lengths;
		} else { // if STMT_EXECUTE was already executed once
			binds=ret->binds;
			is_nulls=ret->is_nulls;
			lengths=ret->lengths;
		}

		// process packet and set NULLs
		for (i=0;i<num_params;i++) {
			uint8_t null_byte=null_bitmap[i/8];
			uint8_t idx=i%8;
			uint8_t tmp_is_null = (null_byte & ( 1 << idx )) >> idx;
			my_bool is_null = tmp_is_null;
			if (new_params_bound_flag == 0) {
				// NOTE: Just impose 'is_null' to be '1' using the values from
				// previous bindings when we know values for these **haven't
				// changed**, this is, when 'new_params_bound_flag' is '0'.
				// Otherwise we will assume a value to be 'NULL' when the
				// binding type could have actually been changed from the
				// previous 'MYSQL_TYPE_NULL'. For more context see #3603.
				if (binds[i].buffer_type == MYSQL_TYPE_NULL)
					is_null = 1;
			}
			is_nulls[i]=is_null;
			binds[i].is_null=&is_nulls[i];
			// set length, defaults to 0
			// for parameters with not fixed length, that will be assigned later
			// we moved this initialization here due to #3585
			binds[i].is_unsigned=0;
			lengths[i]=0;
			binds[i].length=&lengths[i];
			// NOTE: We nullify buffers here to reflect that memory wasn't
			// initalized. See #3546.
			binds[i].buffer = NULL;
		}
		free(null_bitmap); // we are done with it

		if (new_params_bound_flag) {
			// the client is rebinding the parameters
			// the client is sending again the type of each parameter
			for (i=0;i<num_params;i++) {
				// set buffer_type and is_unsigned
				uint16_t buffer_type=0;
				memcpy(&buffer_type,p,2);
				binds[i].is_unsigned=0;
				if (buffer_type >= 32768) { // is_unsigned bit
					buffer_type-=32768;
					binds[i].is_unsigned=1;
				}
				binds[i].buffer_type=(enum enum_field_types)buffer_type;
				// NOTE: This is required because further check for nullity rely on
				// 'is_nulls' instead of 'buffer_type'. See #3603.
				if (binds[i].buffer_type == MYSQL_TYPE_NULL) {
					is_nulls[i]= 1;
				}

				p+=2;

			}
		}

		for (i=0;i<num_params;i++) {
			unsigned long *_l = 0;
			my_bool * _is_null;
			void *_data = (*myds)->sess->SLDH->get(ret->stmt_id, i, &_l, &_is_null);
			if (_data) {
				// Data was sent via STMT_SEND_LONG_DATA so no data in the packet.
				binds[i].length = _l;
				binds[i].buffer = _data;
				binds[i].is_null = _is_null;
				continue;
			} else if (is_nulls[i]==true) {
				// the parameter is NULL, no need to read any data from the packet
				continue;
			}

			enum enum_field_types buffer_type=binds[i].buffer_type;
			switch (buffer_type) {
				case MYSQL_TYPE_TINY:
					binds[i].buffer=p;
					p+=1;
					break;
				case MYSQL_TYPE_SHORT:
				case MYSQL_TYPE_YEAR:
					binds[i].buffer=p;
					p+=2;
					break;
				case MYSQL_TYPE_FLOAT:
				case MYSQL_TYPE_LONG:
				case MYSQL_TYPE_INT24:
					binds[i].buffer=p;
					p+=4;
					break;
				case MYSQL_TYPE_DOUBLE:
				case MYSQL_TYPE_LONGLONG:
					binds[i].buffer=p;
					p+=8;
					break;
				case MYSQL_TYPE_TIME:
					{
						binds[i].buffer=malloc(sizeof(MYSQL_TIME)); // NOTE: remember to free() this
						uint8_t l;
						memcpy(&l,p,1);
						p++;
						MYSQL_TIME ts;
						memset(&ts,0,sizeof(MYSQL_TIME));
						if (l) {
							memcpy(&ts.neg,p,1);
							memcpy(&ts.day,p+1,4);
							memcpy(&ts.hour,p+5,1);
							memcpy(&ts.minute,p+6,1);
							memcpy(&ts.second,p+7,1);
						}
						if (l>8) {
							memcpy(&ts.second_part,p+8,4);
						}
						p+=l;
						memcpy(binds[i].buffer,&ts,sizeof(MYSQL_TIME));
					}
					break;
				case MYSQL_TYPE_DATE:
				case MYSQL_TYPE_TIMESTAMP:
				case MYSQL_TYPE_DATETIME:
					{
						binds[i].buffer=malloc(sizeof(MYSQL_TIME)); // NOTE: remember to free() this
						uint8_t l;
						memcpy(&l,p,1);
						p++;
						MYSQL_TIME ts;
						memset(&ts,0,sizeof(MYSQL_TIME));
						if (l) {
							memcpy(&ts.year,p,2);
							memcpy(&ts.month,p+2,1);
							memcpy(&ts.day,p+3,1);
						}
						if (l>4) {
							memcpy(&ts.hour,p+4,1);
							memcpy(&ts.minute,p+5,1);
							memcpy(&ts.second,p+6,1);
						}
						if (l>7) {
							memcpy(&ts.second_part,p+7,4);
						}
						p+=l;
						memcpy(binds[i].buffer,&ts,sizeof(MYSQL_TIME));
					}
					break;
				case MYSQL_TYPE_DECIMAL:
				case MYSQL_TYPE_VARCHAR:
				case MYSQL_TYPE_BIT:
				case MYSQL_TYPE_JSON:
				case MYSQL_TYPE_NEWDECIMAL:
				case MYSQL_TYPE_ENUM:
				case MYSQL_TYPE_SET:
				case MYSQL_TYPE_TINY_BLOB:
				case MYSQL_TYPE_MEDIUM_BLOB:
				case MYSQL_TYPE_LONG_BLOB:
				case MYSQL_TYPE_BLOB:
				case MYSQL_TYPE_VAR_STRING:
				case MYSQL_TYPE_STRING:
				case MYSQL_TYPE_GEOMETRY:
					{
						uint8_t l=0;
						uint64_t len;
						l=mysql_decode_length((unsigned char *)p, &len);
						if (l>1) {
							PROXY_TRACE();
						}
						p+=l;
						binds[i].buffer=p;
						p+=len;
						lengths[i]=len;
					}
					break;
				default:
					// LCOV_EXCL_START
					proxy_error("Unsupported field type %d in zero-based parameters[%d] "
							"of query %s from user %s with default schema %s\n",
							buffer_type, i, stmt_info->query, stmt_info->username, stmt_info->schemaname);
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
		}
	}
/*
#ifdef DEBUG
	// debug
	fprintf(stderr,"STMT_EXEC: %d\n",ret->stmt_id);
	if (num_params==2) {
		PROXY_TRACE();
	}
	for (int i=0;i<num_params;i++) {
		fprintf(stderr,"  Param %d, is_null=%d, type=%d\n", i, *(ret->binds[i].is_null), ret->binds[i].buffer_type);
	}
#endif
*/
	if (ret)
		ret->size=size;
	return ret;
}

bool MySQL_Protocol::generate_COM_QUERY_from_COM_FIELD_LIST(PtrSize_t *pkt) {
	unsigned int o_pkt_size = pkt->size;
	char *pkt_ptr = (char *)pkt->ptr;

	pkt_ptr+=5;
	// some sanity check
	void *a = NULL;
	a = memchr((void *)pkt_ptr, 0, o_pkt_size-5);
	if (a==NULL) return false; // we failed to parse
	char *tablename = strdup(pkt_ptr);
	unsigned int wild_len = o_pkt_size - 5 - strlen(tablename) - 1;
	char *wild = NULL;
	if (wild_len > 0) {
		pkt_ptr+=strlen(tablename);
		pkt_ptr++;
		wild=strndup(pkt_ptr,wild_len);
	}
	char *q = NULL;
	if ((*myds)->com_field_wild) {
		free((*myds)->com_field_wild);
		(*myds)->com_field_wild=NULL;
	}
	if (wild) {
		(*myds)->com_field_wild=strdup(wild);
	}

	char *qt = (char *)"SELECT * FROM `%s` WHERE 1=0";
	q = (char *)malloc(strlen(qt)+strlen(tablename));
	sprintf(q,qt,tablename);
	l_free(pkt->size, pkt->ptr);
	pkt->size = strlen(q)+5;
	mysql_hdr Hdr;
	Hdr.pkt_id=1;
	Hdr.pkt_length = pkt->size - 4;
	pkt->ptr=malloc(pkt->size);
	memcpy(pkt->ptr,&Hdr,sizeof(mysql_hdr));
    memset((char *)pkt->ptr+4,3,1); // COM_QUERY
    memcpy((char *)pkt->ptr+5,q,pkt->size-5);

	if (wild) free(wild);
	free(tablename);
	free(q);
	return true;
}

my_bool proxy_mysql_stmt_close(MYSQL_STMT* stmt) {
	// Clean internal structures for 'stmt->mysql->stmts'.
	if (stmt->mysql) {
		stmt->mysql->stmts =
			list_delete(stmt->mysql->stmts, &stmt->list);
	}
	// Nullify 'mysql' field to avoid sending a blocking command to the server.
	stmt->mysql = NULL;
	// Perform the regular close operation.
	return mysql_stmt_close(stmt);
}
