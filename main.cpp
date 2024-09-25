#include <iostream>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <cctype>
#include <regex>

#define good 	0
#define error 	1
#define ald 	2

namespace fs = std::filesystem;
using json = nlohmann::json;

int globalCount = 0;

// -----------------------------------------------------------------------------------------------------------------------------
// Структура для хранения информации о версии
struct VersionInfo {
    std::string version;
    std::string status;
};

// Структура для хранения информации о проблемах
struct ProblemType {
    std::string description;
    std::string cweId;
};

// Основная структура для хранения информации о продукте
struct PackageInfo {
    std::string name;
    std::string version;
    std::string vendor;
    std::vector<VersionInfo> versions;
    std::vector<std::string> descriptions;
    std::vector<ProblemType> problemTypes;
    std::string cvssV3_1;
    std::string datePublic;
    
    std::string cveId;
};
// Структура для хранения информации о пакете
/*struct PackageInfo {
    std::string cveId;
    std::vector<std::string> versions;
    std::string cweId;
    double cvssV3_0_baseScore;
};*/
// -----------------------------------------------------------------------------------------------------------------------------

void fillPackageInfo(const json& j, std::vector<PackageInfo>& lib) {
    // Проверка существования контейнеров
    if (j.contains("containers") && 
        j["containers"].contains("cna") && 
        j["containers"]["cna"].contains("affected")) {
        
        const auto& affected = j["containers"]["cna"]["affected"];
        
        // Перебор всех затронутых продуктов
        for (const auto& productInfo : affected) {
            PackageInfo pkgInfo;
            if (productInfo.contains("product"))
                pkgInfo.name = productInfo["product"].get<std::string>();
            if (productInfo.contains("vendor"))
                pkgInfo.vendor = productInfo["vendor"].get<std::string>();
            if (productInfo.contains("versions")) {
                for (const auto& version : productInfo["versions"]) {
                    VersionInfo versionInfo;
                    if (version.contains("version"))
                        versionInfo.version = version["version"].get<std::string>();
                    if (version.contains("status"))
                        versionInfo.status = version["status"].get<std::string>();
                    pkgInfo.versions.push_back(versionInfo);
                }
            }
            if (j["containers"]["cna"].contains("descriptions")) {
                for (const auto& description : j["containers"]["cna"]["descriptions"]) {
                    if (description.contains("value")) {
                        pkgInfo.descriptions.push_back(description["value"].get<std::string>());
                    }
                }
            }
            if (j["containers"]["cna"].contains("problemTypes")) {
                for (const auto& problemType : j["containers"]["cna"]["problemTypes"]) {
                    ProblemType probType;
                    if (problemType.contains("descriptions")) {
                        for (const auto& desc : problemType["descriptions"]) {
                            if (desc.contains("description")) {
                                probType.description = desc["description"].get<std::string>();
                            }
                            if (desc.contains("cweId")) {
                                probType.cweId = desc["cweId"].get<std::string>();
                            }
                        }
                    }
                    pkgInfo.problemTypes.push_back(probType);
                }
            }
            if (j["containers"]["cna"].contains("datePublic")) {
                pkgInfo.datePublic = j["containers"]["cna"]["datePublic"].get<std::string>();
            }
            if (j["containers"]["cna"].contains("metrics") &&
                j["containers"]["cna"]["metrics"].contains("cvssV3_1") &&
                j["containers"]["cna"]["metrics"]["cvssV3_1"].contains("baseScore")) {
                //pkgInfo.cvssV3_1 = j["containers"]["cna"]["metrics"]["cvssV3_1"]["baseScore"].get<double>();
                pkgInfo.cvssV3_1 = j["containers"]["cna"]["metrics"]["cvssV3_1"]["baseScore"].get<std::string>();
            }
            lib.push_back(pkgInfo);
        }
    }
}

// Функция для извлечения данных из JSON и записи их в файл
/*void extractAndWriteToFile(const json& j, const std::string& filename) {
    if (j.contains("containers") && 
        j["containers"].contains("cna") && 
        j["containers"]["cna"].contains("affected")) {

        // Открываем файл для добавления (append mode)
        std::ofstream outFile(filename, std::ios_base::app);

        if (!outFile.is_open()) {
            std::cerr << "Error: Could not open the file " << filename << std::endl;
            return;
        }

        for (const auto& affected : j["containers"]["cna"]["affected"]) {
            PackageInfo pkgInfo;

            // Извлечение данных
            if (j.contains("cveId")) {
                pkgInfo.cveId = j["cveId"].get<std::string>();
            }
            if (affected.contains("product")) {
                pkgInfo.product = affected["product"].get<std::string>();
            }
            if (affected.contains("versions")) {
                for (const auto& version : affected["versions"]) {
                    if (version.contains("version")) {
                        pkgInfo.versions.push_back(version["version"].get<std::string>());
                    }
                }
            }
            if (j.contains("cwe")) {
                if (!j["cwe"].empty() && j["cwe"][0].contains("id")) {
                    pkgInfo.cweId = j["cwe"][0]["id"].get<std::string>();
                }
            }
            if (j.contains("cvssV3")) {
                if (j["cvssV3"].contains("baseScore")) {
                    pkgInfo.cvssV3_0_baseScore = j["cvssV3"]["baseScore"].get<double>();
                }
            }

            // Запись данных в файл
            outFile << "CVE ID: " << pkgInfo.cveId << std::endl;
            outFile << "Product: " << pkgInfo.product << std::endl;
            outFile << "Versions: ";
            for (size_t i = 0; i < pkgInfo.versions.size(); ++i) {
                outFile << pkgInfo.versions[i];
                if (i != pkgInfo.versions.size() - 1) {
                    outFile << ", ";
                }
            }
            outFile << std::endl;
            outFile << "CWE ID: " << pkgInfo.cweId << std::endl;
            outFile << "CVSS v3.0 Base Score: " << pkgInfo.cvssV3_0_baseScore << std::endl;
            outFile << "------------------------" << std::endl;
        }

        // Закрываем файл
        outFile.close();
    }
}*/


void showDataCve(PackageInfo& pkg) {
	// Выводим данные
        std::cout << "Product: " << pkg.name << "\n";
        std::cout << "Vendor: " << pkg.vendor << "\n";
        std::cout << "Date Public: " << pkg.datePublic << "\n";
        std::cout << "CVSS v3.1: " << pkg.cvssV3_1 << "\n";
        std::cout << "Versions:\n";
        for (const auto& ver : pkg.versions) {
            std::cout << "  - Version: " << ver.version << " Status: " << ver.status << "\n";
        }
        std::cout << "Descriptions:\n";
        for (const auto& desc : pkg.descriptions) {
            std::cout << "  - " << desc << "\n";
        }
        std::cout << "Problem Types:\n";
        for (const auto& prob : pkg.problemTypes) {
            std::cout << "  - Description: " << prob.description;
            if (!prob.cweId.empty()) {
                std::cout << " CWE ID: " << prob.cweId;
            }
            std::cout << "\n";
        }
}

// Функция для записи данных в файл
void writePackageInfoToFile(const std::vector<PackageInfo>& lib, const std::string& filename) {
    std::ofstream outfile(filename);
    // Проверка, что файл открылся успешно
    if (!outfile.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }
    // Записываем данные о каждом продукте
    for (const auto& pkg : lib) {
        outfile << "Product: " << pkg.name << "\n";
        outfile << "Vendor: " << pkg.vendor << "\n";
        outfile << "Date Public: " << pkg.datePublic << "\n";
        outfile << "CVSS v3.1: " << pkg.cvssV3_1 << "\n";
        outfile << "Versions:\n";
        for (const auto& ver : pkg.versions) {
            outfile << "  - Version: " << ver.version << " Status: " << ver.status << "\n";
        }
        outfile << "Descriptions:\n";
        for (const auto& desc : pkg.descriptions) {
            outfile << "  - " << desc << "\n";
        }
        outfile << "Problem Types:\n";
        for (const auto& prob : pkg.problemTypes) {
            outfile << "  - Description: " << prob.description;
            if (!prob.cweId.empty()) {
                outfile << " CWE ID: " << prob.cweId;
            }
            outfile << "\n";
        }
        outfile << "-------------------------------------------------------------------   \n";
    }
    // Закрываем файл
    outfile.close();
}


bool getOSVersion(std::string& osName, std::string& osVersion) {
    FILE* file = popen("lsb_release -a 2>/dev/null", "r");
    if (!file) {
        std::cerr << "Failed to run lsb_release command." << std::endl;
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        std::string lineStr(line);

        // Поиск строки с названием ОС
        if (lineStr.find("Distributor ID:") != std::string::npos) {
            osName = lineStr.substr(lineStr.find(':') + 1);
            osName.erase(0, osName.find_first_not_of(" \t"));  // Удаление пробелов в начале
        }

        // Поиск строки с версией ОС
        if (lineStr.find("Release:") != std::string::npos) {
            osVersion = lineStr.substr(lineStr.find(':') + 1);
            osVersion.erase(0, osVersion.find_first_not_of(" \t"));  // Удаление пробелов в начале
        }
    }

    pclose(file);

    // Проверка, удалось ли получить данные
    if (osName.empty() || osVersion.empty()) {
        std::cerr << "Could not determine OS name or version." << std::endl;
        return false;
    }

    return true;
}


// Функция для получения установленных пакетов и их версий
std::vector<PackageInfo> getInstalledPackages() {
    std::vector<PackageInfo> packages;
    FILE* pipe = popen("dpkg-query -W -f='${Package} ${Version}\n'", "r");
    if (!pipe) {
        std::cerr << "Failed to run command." << std::endl;
        return packages;
    }
    char line[256];
    while (fgets(line, sizeof(line), pipe)) {
        // Найти позицию первого пробела
        char* space = strchr(line, ' ');
        if (space) {
            *space = '\0'; // Разделить строку на имя пакета и версию
            std::string packageName(line);
            std::string packageVersion(space + 1);

            // Удалить символ новой строки в конце версии
            if (!packageVersion.empty() && packageVersion.back() == '\n') {
                packageVersion.pop_back();
            }
            // Добавить пакет в вектор
            packages.push_back(PackageInfo{packageName, packageVersion});
        }
    }
    pclose(pipe);
    return packages;
}

// Сравнение результатов
bool checkResutls(int result, const std::string& versionCve, const std::string& versionLib, const std::string& name) {
    if (result == good) {
	std::cout << "\033[32m" << "A LIBRARY - " << name << "- VERSION - " << versionLib << " - passed the test successfully. In CVE findede version - "  << versionCve << "\033[0m" << std::endl;
	
    } else if (result == ald) {
	std::cout << "\033[33m" << "A LIBRARY - " << name << " - outdated version - " << versionLib << " - was found in the system. However, the new version - " << versionCve << " also has a vulnerability" << "\033[0m" << std::endl;
    } else if (result == error) {
	std::cout << "\033[31m" << "!!! A library - " << name << " - version - " << versionLib << " - with a vulnerability was detected in the system. In CVE finded version " << versionCve << "\033[0m" << std::endl;
	return true;
    }
    return false;
}

// Сравнение посимвольно
int compareVersions(const std::string& versionCve, const std::string& versionSystme) {
    size_t i = 0, j = 0;
    if(versionCve.length() == versionSystme.length()) {
      	while (i < versionCve.length() && j < versionSystme.length()) {
            if (versionCve[i] < versionSystme[j]) {
            	return 0;  // Вторая версия новее
            }
            if (versionCve[i] > versionSystme[j]) {
            	return 2;  // Первая версия новее
            }
            ++i;
            ++j;
    	}
    	return 1;  // Версии равны
    }
    return 3;
}

// Удаление символов до : включительно
std::string removeUpToColon(const std::string& input) {
    std::string result = input;
    size_t colonPos = result.find(':');
    if (colonPos != std::string::npos) {
        result = result.substr(colonPos + 1);  // Обрезаем строку начиная с символа после двоеточия
    }
    return result;
} 

std::string extractVersionNew(const std::string& versionString) {
    // Регулярное выражение для поиска основной части версии
    std::regex versionRegex(R"(\b(\d+\.\d+(?:\.\d+)?)\b)");
    std::smatch match;

    // Ищем первую подходящую версию
    if (std::regex_search(versionString, match, versionRegex)) {
        // Возвращаем найденную версию
        return match.str(0);
    }

    return "";  // Возвращаем пустую строку, если версия не найдена
}

std::vector<std::string> extractVersions(const std::string& input) {
    std::vector<std::string> versions;
    std::regex versionPattern(R"((\d+(\.\d+)+))");
    std::smatch match;
    std::string::const_iterator searchStart(input.cbegin());

    // Ищем все версии в строке и добавляем их в массив
    while (std::regex_search(searchStart, input.cend(), match, versionPattern)) {
        versions.push_back(match[0]);
        searchStart = match.suffix().first;
    }

    return versions;
}

// Функция для сравнения двух версий
int compareVersionsTwoVersions(const std::string& version1, const std::string& version2) {
    std::istringstream v1(version1);
    std::istringstream v2(version2);
    std::string part1, part2;
    while (std::getline(v1, part1, '.') || std::getline(v2, part2, '.')) {
        int num1 = part1.empty() ? 0 : std::stoi(part1);
        int num2 = part2.empty() ? 0 : std::stoi(part2);
        if (num1 < num2) return -1; // version1 < version2
        if (num1 > num2) return 1;  // version1 > version2
        part1.clear();
        part2.clear();
    }
    return 0; // Если версии равны
}

// Функция для преобразования строки версии в вектор целых чисел
std::vector<int> versionToVector(const std::string& version) {
    std::vector<int> versionVector;
    std::string number;
    for (char ch : version) {
        if (ch == '.') {
            if (!number.empty()) {
                versionVector.push_back(std::stoi(number));
                number.clear();
            }
        } else if (std::isdigit(ch)) {
            number += ch;
        }
    }
    if (!number.empty()) {
        versionVector.push_back(std::stoi(number));
    }
    return versionVector;
}

// Функция для сравнения двух версий
int compareVersionInt(const std::string& v1, const std::string& v2) {
    std::vector<int> ver1 = versionToVector(v1);
    std::vector<int> ver2 = versionToVector(v2);

    size_t maxSize = std::max(ver1.size(), ver2.size());
    for (size_t i = 0; i < maxSize; ++i) {
        int part1 = i < ver1.size() ? ver1[i] : 0;
        int part2 = i < ver2.size() ? ver2[i] : 0;
        if (part1 < part2) return -1;
        if (part1 > part2) return 1;
    }
    return 0;
}

// Основная функция для сравнения версии с множеством версий
int compareVersionWithList(const std::vector<std::string>& versions, const std::string& targetVersion) {
    bool hasOlder = false;
    bool hasNewer = false;
    if (versions.size() == 2) {
        // Если в списке две версии, это диапазон
        int compStart = compareVersionInt(targetVersion, versions[0]);
        int compEnd = compareVersionInt(targetVersion, versions[1]);
        if (compStart >= 0 && compEnd <= 0) {
            return 1; // Версия попадает в диапазон
        }/* else {
            return 2; // Версия не попадает в диапазон
        }*/
    }
    for (const auto& version : versions) {
    	//std::cout << "     2 EASY VERSION LIBRARY in CVE: " << version << std::endl;
        int comparisonResult = compareVersionsTwoVersions(targetVersion, version);
        if (comparisonResult == 0) {
            return 1; // Найдено точное совпадение
        } else if (comparisonResult < 0) {
            hasNewer = true; // Найдена более новая версия
        } else {
            hasOlder = true; // Найдена более старая версия
        }
    }
    if (hasNewer) {
        return 2; // Есть более новая версия
    } else if (hasOlder) {
        return 0; // Все версии старее
    }
    return -1; // Этот случай должен быть невозможным, так как всегда есть хотя бы одна версия
}


// Функция для получения значения product из JSON
bool isMatch(const json& j, 
	const std::string& osName, 
	const std::string& osVersion, 
	std::vector<PackageInfo>& lib, 
	std::vector<PackageInfo>& cve,
	const std::string& argument) {
    // Проверяем, содержится ли информация об "affected"
    if (j.contains("containers") && 
        j["containers"].contains("cna") && 
        j["containers"]["cna"].contains("affected")) {

        for (const auto& affectedItem : j["containers"]["cna"]["affected"]) {
            if (affectedItem.contains("product")) {
                std::string product = affectedItem["product"].get<std::string>();
                if (product.find(osName) != std::string::npos) {
                    std::cout << "Partial product match found: " << product << std::endl;
                    return true;
                } 
                for (const auto& pkg : lib) {
        	    if(product == pkg.name) {
                    	if (affectedItem.contains("versions")) {
             		    std::string version;
             		    //std::cout << "Lib - " << pkg.name << " - version " << pkg.version << std::endl;	
             		    for (const auto& firstAffectedVersionItem : affectedItem["versions"]) {
         			if (firstAffectedVersionItem.contains("version")) { 
        			    version = firstAffectedVersionItem["version"].get<std::string>();
        			    if (version == "unspecified" || version == "0" || version == "") {
        				if (firstAffectedVersionItem.contains("lessThan")) {
            				    version = firstAffectedVersionItem["lessThan"].get<std::string>();  
            				    if (version == "unspecified" || version == "0" || version == "") {
            					version = "0";
            				    }   							
        				} else 
        				    version = "0";
        			    }
        			    //std::cout << "  VERSION LIBRARY in CVE: " << version << std::endl;
        			    if (checkResutls(compareVersions(version, pkg.version), version, pkg.version, pkg.name)) {
        				fillPackageInfo(j, cve);
        				    return true;
        			    }
        			    if (pkg.version.find(':') != std::string::npos) {
            				std::string withoutDot = removeUpToColon(pkg.version);
            				if (checkResutls(compareVersions(version, withoutDot), version, withoutDot, pkg.name)) {
        				    fillPackageInfo(j, cve);
        				    return true;
        				}
            			    }
            			    // Мягкая привязка
            			    if (argument == "2") {
    				    	std::string cveCorrectVersion = extractVersionNew(version);
    				    	//std::cout << "  EASY VERSION LIBRARY in CVE: " << cveCorrectVersion << std::endl;
    				    	std::string libCorrectVersion = extractVersionNew(pkg.version);
    				    	//std::cout << "  EASY VERSION LIBRARY in OS: " << libCorrectVersion << std::endl;
    				    	if (checkResutls(compareVersions(cveCorrectVersion, libCorrectVersion), version, pkg.version, pkg.name)) {
        				    fillPackageInfo(j, cve);
        				    return true;
        			    	}
        			    	std::vector<std::string> versions = extractVersions(version);
        			    	if (checkResutls(compareVersionWithList(versions, libCorrectVersion), version, pkg.version, pkg.name)) {
        				    fillPackageInfo(j, cve);
        				    return true;
        			    	}   
        			    }					
    				    //
    					
    					// ////////////////////////////////////	
    						
        			    } else if (firstAffectedVersionItem.contains("lessThan")) {
        				version = firstAffectedVersionItem["lessThan"].get<std::string>();
        				if (version == "unspecified" || version == "0" || version == "") {
        				    version = "0";
        				}
        				//std::cout << "  VERSION LIBRARY in CVE: " << version << std::endl;
        				if (checkResutls(compareVersions(version, pkg.version), version, pkg.version, pkg.name)) {
        				    fillPackageInfo(j, cve);
        				    return true;
        				}
        				if (pkg.version.find(':') != std::string::npos) {
            				    std::string withoutDot = removeUpToColon(pkg.version);
            				    if (checkResutls(compareVersions(version, withoutDot), version, withoutDot, pkg.name)) {
        					fillPackageInfo(j, cve);
        					return true;
        				    }
            				}
                			// Мягкая привязка
                			if (argument == "2") {
    					    std::string cveCorrectVersion = extractVersionNew(version);
    					    std::string libCorrectVersion = extractVersionNew(pkg.version);
    					    if (checkResutls(compareVersions(cveCorrectVersion, libCorrectVersion), version, pkg.version, pkg.name)) {
        				    	fillPackageInfo(j, cve);
        				    	return true;
        				    }
        				    std::vector<std::string> versions = extractVersions(version);
        				    if (checkResutls(compareVersionWithList(versions, libCorrectVersion), version, pkg.version, pkg.name)) {
        					fillPackageInfo(j, cve);
        					return true;
        				    }  
        				}
        			} else {
        					std::cout << "\033[33m" << "Version in CVE not finded ??? " << "\033[0m" << std::endl;
        			}
        		    }
                    	}
                    }
                }
            }
        }
    }
    return false;
}

// Функция для обхода директорий и копирования файлов
void processDirectory(const fs::path& inputDir, 
		const fs::path& outputDir, 
		const std::string& osName, 
		const std::string& osVersion,
		const std::string& argument,
		std::vector<PackageInfo>& lib,
		std::vector<PackageInfo>& cve) {
    if (!fs::exists(outputDir)) {
        fs::create_directories(outputDir);
    }

    for (const auto& entry : fs::recursive_directory_iterator(inputDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            std::ifstream inputFile(entry.path());
            //std::cout << "PATH: " << entry.path() << std::endl;
            if (!inputFile) {
                std::cerr << "Cannot open file: " << entry.path() << std::endl;
                continue;
            }
            json j;
            try {
                inputFile >> j;
            } catch (json::exception& e) {
                std::cerr << "Error parsing JSON in file: " << entry.path() << " (" << e.what() << ")" << std::endl;
                continue;
            }

            if (isMatch(j, osName, osVersion, lib, cve, argument)) {
                fs::path destFile = outputDir / entry.path().filename();
                fs::copy_file(entry.path(), destFile, fs::copy_options::overwrite_existing);
                std::cout << "Copied file: " << entry.path() << " to " << destFile << std::endl;
                //showDataCve(cve.back());
                std::cout << "№" << ++globalCount << " -----------------------------------------------------------" << std::endl;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Select the further way (number) of the program operation in argument programm: " << std::endl;
    	std::cout << " 1 - Hard version binding (Specific system) " << std::endl;
    	std::cout << " 2 - Soft version binding (Suitable for all systems) " << std::endl;
        return 1; // Возвращаем код ошибки
    }

    std::string argument = argv[1];
    
    std::string osName, osVersion;
    if (getOSVersion(osName, osVersion)) {
        std::cout << "OS Name: " << osName << std::endl;
        std::cout << "OS Version: " << osVersion << std::endl;
    } else {
        std::cerr << "Failed to get OS version." << std::endl;
    }

    std::vector<PackageInfo> packages = getInstalledPackages();
    std::vector<PackageInfo> cve;

    std::cout << "Installed packages and their versions:" << std::endl;
    for (const auto& pkg : packages) {
        std::cout << pkg.name << " " << pkg.version << std::endl;
    }

    fs::path inputDir = "cvelistV5-main/cves";
    fs::path outputDir = "matched_cves";

    processDirectory(inputDir, outputDir, osName, osVersion, argument, packages, cve);
    
     // Записываем данные в файл
    writePackageInfoToFile(cve, "result.txt");

    return 0;
}
