#ifndef __CLASS_PROXYSQL_CONFIGFILE_H
#define __CLASS_PROXYSQL_CONFIGFILE_H

#include "libconfig.h++"

using namespace libconfig;


class ProxySQL_ConfigFile {
  private:
  //struct stat statbuf;
  std::string filename;
  public:
  Config cfg;
  bool OpenFile(const char *);
  void CloseFile();
  bool ReadGlobals();
  int get_int(const char* section, const char* key, int default_value) {
      try {
          return cfg.lookup(section)[key];
      } catch (...) {
          return default_value;
      }
  }

  std::string get_string(const char* section, const char* key, const std::string& default_value) {
      try {
          return std::string(cfg.lookup(section)[key].c_str());
      } catch (...) {
          return default_value;
      }
  }
};


#endif /* __CLASS_PROXYSQL_CONFIGFILE_H */
