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
#include <curl/curl.h>
#include <thread>   // Для std::this_thread::sleep_for
#include <chrono>   // Для std::chrono

#define good 	0
#define error 	1
#define ald 	2

// g++ -o cve main.cpp  -lcurl
// ./cve 1 (3) 
// Алгоритм !
// 1 - сравнить версию с "changes":"at". И если точно попали то уязвимости нет. Если не точно, то переходим ко 2 пункту.
// 2 - сравнить версию с "versions":"lessThan" или с "versions":"lessThanEqual ?". Если меньше то уязвимость, если больше здоровый. Если lessThan нет, то пункт 3. 
// 3 - сравнить версию с "versions":"version". Если нашли точное значение или попали в диапазон, то уязвимость. Если нет то пункт 4.
// 4 - скопировать файл .json в директорию для указания пользователю проверить его в ручную. 

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


// Функция для записи данных в файл
size_t WriteCallback(void* contents, size_t size, size_t nmemb, FILE* userp) {
    size_t totalSize = size * nmemb;
    fwrite(contents, size, nmemb, userp);
    return totalSize;
}

// Функция для загрузки файла
bool downloadFile(const std::string& url, const std::string& outputPath) {
    CURL* curl;
    FILE* file;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        file = fopen(outputPath.c_str(), "wb");
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        res = curl_easy_perform(curl);
        fclose(file);
        curl_easy_cleanup(curl);
        return (res == CURLE_OK);
    }
    return false;
}

// Функция для распаковки ZIP-файла с помощью команды unzip
void unzipFile(const std::string& zipFilePath) {
    std::string command = "unzip " + zipFilePath;
    system(command.c_str());
}

// Функция для отображения анимации загрузки
void showLoadingAnimation() {
    const char* animationChars = "|/-\\";
    while (true) {
        for (int i = 0; i < 4; ++i) {
            std::cout << "\rDownloading... " << animationChars[i] << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
}

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

// Функция для сравнения двух версий
/*int compareVersionsTwoVersions(const std::string& version1, const std::string& version2) {
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
}*/

// Функция для преобразования строки версии в вектор целых чисел
/*std::vector<int> versionToVector(const std::string& version) {
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
}*/

void toLowerIfContainsUpper(std::string str) {
    if (std::any_of(str.begin(), str.end(), ::isupper)) {
        std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    }
}

// Функция для получения значения product из JSON
/*bool isMatch(const json& j,
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
                // Проверка на пустоту в продукте
                if (product.find(osName) != std::string::npos) {
                    std::cout << "Partial product match found: " << product << std::endl;
                    return true;
                } 
                for (const auto& pkg : lib) {
                    // Приводим названия продуктов к общему регистру
                    toLowerIfContainsUpper(product);
                    toLowerIfContainsUpper(pkg.name);
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
}*/

bool isMatch(const json& j,
	const std::string& osName,
	const std::string& osVersion,
	std::vector<PackageInfo>& lib,
	std::vector<PackageInfo>& cve,
	const std::string& argument) {
    // Проверяем, содержится ли информация об "affected"
    if (j.contains("containers") && j["containers"].contains("cna") && j["containers"]["cna"].contains("affected")) {
        for (const auto& affected : j["containers"]["cna"]["affected"]) {
            // Проверяем, содержится ли информация об "product"
            if (affected.contains("product")) {
                std::string product = affected["product"].get<std::string>();
                // Проверка на пустоту в "product"
                if (product.find(osName) != std::string::npos) {
                    //std::cout << "Partial product match found: " << product << std::endl;
                    return true;
                }
                for (const auto& pkg : lib) {
                    // Приводим названия продуктов к общему регистру
                    toLowerIfContainsUpper(product);
                    toLowerIfContainsUpper(pkg.name);
                    if(product == pkg.name) {
                        // Проверяем, содержится ли информация об "versions"
                        if (affected.contains("versions")) {
                            for (const auto& version : affected["versions"]) {
                                //std::cout << "Lib in System is: " << pkg.name << "; \t version: " << pkg.version << std::endl;
                                //std::cout << "Lib in CVE is - " << product << "; \t";
                                if (version.contains("version")) {
                                    //std::cout << "\033[33m" << "version: " << version["version"] << "\033[0m" << std::endl;
                                    //std::cout << version["version"] << std::endl;
                                }
                                if (version.contains("lessThan")) {
                                    //std::cout << "\033[33m" << "lessThan: " << version["lessThan"] << "\033[33m" << std::endl;
                                    //std::cout << version["lessThan"] << std::endl;
                                }
                                if (version.contains("lessThanOrEqual")) {
                                    //std::cout << "\033[33m" << "lessThanOrEqual: " << version["lessThanOrEqual"] << "\033[33m" << std::endl;
                                    //std::cout << version["lessThanOrEqual"] << std::endl;
                                }
                                if (version.contains("changes")) {
                                    for (const auto& change : version["changes"]) {
                                        if (change.contains("at")) {
                                            //std::cout << "\033[32m" << "Patch at: " << change["at"] << "\033[32m" << std::endl;
                                            std::cout << change["at"] << std::endl;
                                        }
                                    }
                                }
                            }
                            return true;
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
                //std::cout << "Copied file: " << entry.path() << " to " << destFile << std::endl;
                //std::cout << "№" << ++globalCount << " -----------------------------------------------------------" << std::endl;
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Select the further way (number) of the program operation in argument programm: " << std::endl;
    	std::cout << " 1 - Hard version binding (Specific system) " << std::endl;
    	std::cout << " 2 - Soft version binding (Suitable for all systems) " << std::endl;
    	std::cout << " 3 - Download Data Base CVE " << std::endl;
        return 1; // Возвращаем код ошибки
    }

    std::string argument = argv[1];
    
    if (argument == "3") {
    	const std::string url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip";
    	// Получаем путь к текущему исполняемому файлу
	fs::path execPath = fs::current_path();
    	const std::string outputPath = (execPath / "main.zip").string();
    	// Запускаем анимацию в отдельном потоке
    	std::cout << "Database loading speed depends on your internet connection" << std::endl;
    	std::cout << "The update may take several minutes" << std::endl;
    	std::thread loadingThread(showLoadingAnimation);
    	// Скачиваем ZIP-файл
    	if (downloadFile(url, outputPath)) {
    		// Останавливаем анимацию загрузки
    		loadingThread.detach(); // Отсоединяем поток
    		std::cout << "\rDownload complete.                     " << std::endl;
    		// Распаковываем ZIP-файл
        	unzipFile(outputPath);
        	std::cout << "Data base CVE was update successfull" << std::endl;
    	} else {
    		// Останавливаем анимацию загрузки
    		loadingThread.detach(); // Отсоединяем поток
    		std::cout << "\rDownload complete.                     " << std::endl;
    		std::cerr << "Data base CVE NOT UPDATE ! \n Check your connect with Ethernet" << std::endl;
	}
    	return 0;
    }
    
    
    std::string osName, osVersion;
    if (getOSVersion(osName, osVersion)) {
        std::cout << "OS Name: " << osName << std::endl;
        std::cout << "OS Version: " << osVersion << std::endl;
    } else {
        std::cerr << "Failed to get OS version." << std::endl;
    }

    std::vector<PackageInfo> packages = getInstalledPackages();
    std::vector<PackageInfo> cve;

    //std::cout << "Installed packages and their versions:" << std::endl;
    for (const auto& pkg : packages) {
        //std::cout << pkg.name << " " << pkg.version << std::endl;
    }

    fs::path inputDir = "cvelistV5-main/cves";
    fs::path outputDir = "matched_cves";

    processDirectory(inputDir, outputDir, osName, osVersion, argument, packages, cve);
    
     // Записываем данные в файл
    writePackageInfoToFile(cve, "result.txt");

    return 0;
}
