/*
 * openvas.cpp
 * Copyright (C) 2020 peeweep <peeweep@0x0.ee>
 *
 * Distributed under terms of the MIT license.
 */

#include <iostream>
#include <pugixml.hpp>
#include <regex>
#include <string>
#include <vector>

class Package {
 public:
  Package() {}
  Package(std::string name, std::string package, std::string installed_version,
          std::string fixed_version, std::string security_information_xref,
          std::string security_tracker_xref, std::string threat, std::string severity)
      : m_name(name),
        m_package(package),
        m_installed_version(installed_version),
        m_fixed_version(fixed_version),
        m_security_information_xref(security_information_xref),
        m_security_tracker_xref(security_tracker_xref),
        m_threat(threat),
        m_severity(severity) {}
  void show_members() {
    std::cout << m_name << "," << m_package << "," << m_installed_version << ","
              << m_fixed_version << "," << m_security_information_xref << ","
              << m_security_tracker_xref << "," << m_threat << "," << m_severity << std::endl;
  }

 private:
  std::string m_name;
  std::string m_package;
  std::string m_installed_version;
  std::string m_fixed_version;
  std::string m_security_information_xref;
  std::string m_security_tracker_xref;
  std::string m_threat;
  std::string m_severity;
};

int main(int argc, const char* argv[]) {
  pugi::xml_document     doc;
  pugi::xml_parse_result results = doc.load_file(argv[1]);

  if (!results) {
    return -1;
  }

  std::vector<Package> pkgs;

  for (auto result : doc.child("get_results_response").children("result")) {
    auto        name        = result.child("name").child_value();
    std::string description = result.child("description").child_value();

    auto threat   = result.child("threat").child_value();
    auto severity = result.child("severity").child_value();

    // parse xref to security_information_xref and security_tracker_xref
    std::string xref = result.child("nvt").child("xref").child_value();
    std::string first_split_keyword("URL:"), second_split_keyword(", ");
    auto        security_information_xref =
        xref.substr(xref.find(first_split_keyword) + first_split_keyword.length(),
                    xref.find(second_split_keyword) - first_split_keyword.length());
    xref = xref.erase(0, xref.find(second_split_keyword) + second_split_keyword.length());
    auto security_tracker_xref = xref.erase(0, first_split_keyword.length());
    // end parse

    // parse description
    std::vector<std::string> regex_strings;
    regex_strings.push_back("Vulnerable package: .*");
    regex_strings.push_back("Installed version:  .*");
    regex_strings.push_back("Fixed version:      .*");

    std::smatch sm_result;

    // package name
    std::vector<std::string> package_names;

    while (std::regex_search(description, sm_result, std::regex(regex_strings[0]))) {
      for (std::string i : sm_result) {
        std::string package_name =
            i.replace(i.begin(), i.begin() + regex_strings[0].length() - 2, "");
        package_names.push_back(package_name);
      }
      description = sm_result.suffix().str();
    }

    // installed version

    std::string installed_version;
    while (std::regex_search(description, sm_result, std::regex(regex_strings[1]))) {
      description = sm_result.suffix().str();
      auto* pkg   = new Package();
      for (std::string i : sm_result) {
        installed_version = i.replace(i.begin(), i.begin() + regex_strings[1].length() - 2, "");
      }
    }

    // fixed version

    std::string fixed_version;
    while (std::regex_search(description, sm_result, std::regex(regex_strings[2]))) {
      description = sm_result.suffix().str();
      auto* pkg   = new Package();
      for (std::string i : sm_result) {
        fixed_version = i.replace(i.begin(), i.begin() + regex_strings[2].length() - 2, "");
      }
    }

    for (auto package_name : package_names) {
      pkgs.push_back(Package(name, package_name, installed_version, fixed_version,
                             security_information_xref, security_tracker_xref, threat, severity));
    }

    // end parse description
  }
  std::cout << "name,package,installed version,fixed version,security information,security "
               "tracker,threat,severity"
            << std::endl;

  for (auto pkg : pkgs) {
    pkg.show_members();
  }
  return 0;
}