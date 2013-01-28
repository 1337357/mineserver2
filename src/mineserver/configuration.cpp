/*
  Copyright (c) 2013, The Mineserver Project
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 * Neither the name of the The Mineserver Project nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sstream>
#include <iostream>
#include <fstream>

#include "configuration.h"

bool Mineserver::Configuration::loadGlobalConfig(std::string location){
  std::ifstream configfile;
  configfile.open(location.c_str(), std::ios::in);
  if(configfile.is_open()){
    std::cout << "mineserver.conf found, attempting to parse it..." << std::endl;
    std::string line;
    while(configfile.good()){
      std::getline(configfile, line);

      int commentPos = line.find("#");
      if(commentPos >= 0) {
        //we found a comment in the line somewhere.
        if(commentPos == 0){
          //first char is comment. Completely ignore the line
          continue;
        }

        std::cout << "We found an inline comment char at:" << commentPos << ", truncating it" << std::endl;
        std::cout << "Line size is: " << line.size() << std::endl;
        line = line.substr(0, commentPos);
        std::cout << "Line size is now (truncated): " << line.size() << std::endl;
      }

      int delimPos = line.find("=");
      if(delimPos < 0){
        //ignore garbage line without = sign.
        continue;
      }
      config[ line.substr(0, delimPos) ] = line.substr(delimPos + 1, line.size() - 1);
      std::cout << "Key: " << line.substr(0, delimPos) << " = " << line.substr(delimPos + 1, line.size() - 1) << std::endl;
    }

    configfile.close();
  }

  else {
    //file does not exist. create it and add defaults
    configfile.close();
    std::ofstream outputfile;
    outputfile.open(location.c_str(), std::ios::out);
    if(outputfile.is_open()){
      outputfile <<
          "#Mineserver2 Default Configuration\n" <<
          "host=localhost\n" <<
          "port=25565\n" <<
          "motd=Mineserver 2.0\n";
      outputfile.close();
      std::cout << "Default configuration generated." << std::endl;
      loadGlobalConfig(location);
    }
    else {
      std::cout << "Something went wrong with generating the config. Is the folder write-protected?" << std::endl;
      configfile.close();
    }
  }
  return true;
}

std::string Mineserver::Configuration::getString(std::string key){
  if(config.find(key) == config.end()){
    std::cout << "Configuration Error: key " << key << " does not have a set value!" << std::endl;
  }
  return config[key];
}

int Mineserver::Configuration::getInt(std::string key){
  if(config.find(key) == config.end()){
    std::cout << "Configuration Error: key " << key << " does not have a set value!" << std::endl;
    return 0;
  }
  int result;
  std::stringstream keyToInt(config[key]);
  keyToInt >> result;
  return result;
}

bool Mineserver::Configuration::getBool(std::string key){
  if(config.find(key) == config.end()){
    std::cout << "Configuration Error: key " << key << " does not have a set value!" << std::endl;
    return false;
  }
  bool result;
  std::stringstream keyToBool(config[key]);
  keyToBool >> result;
  return result;
}
