
#include <stdio.h>
#include <windows.h>
#include <conio.h>
#include <math.h>
#include <iostream>
#include <atlstr.h>
#include <vector>

#define LOGICAL_SECTOR_SIZE			0x200

#define MBR_STATUS_NON_BOOTABLE     0x00
#define MBR_STATUS_NON_BOOTABLE_LBA 0x01
#define MBR_STATUS_BOOTABLE         0x80
#define MBR_STATUS_BOOTABLE_LBA     0x81

#define MBR_TYPE_UNUSED             0x00
#define MBR_TYPE_NTFS               0x07
#define MBR_TYPE_LINUX              0x83
#define MBR_TYPE_FAT32              0x0B
#define MBR_TYPE_FAT32_LBA          0x0C


struct partition {
	BYTE type;
	long long int otn_adr;
	long long int size;
	long int serialNumber;
};

struct mbr {
	long long int adr;
	partition pt[4];
} mbr_t;

typedef struct drive {
	TCHAR name[4];
	uint32_t SerialN;

}drive_t;

std::vector<drive_t> drives;



void scanDrives() {					//находит те, что видны в Win, заносит в вектор


    BOOL bFlag;
    TCHAR Buf[MAX_PATH];           //  буфер для volume name
	DWORD SerialNumber;

    std::string s;
    TCHAR szDrive = 'A';
    DWORD drives_mask = GetLogicalDrives();


    if (drives_mask == 0)

        printf("GetLogicalDrives() failed with failure code: %d\n", GetLastError());

    else

    {

        while (drives_mask)

        {

            if (drives_mask & 1)	s.push_back(szDrive);

            ++szDrive;
            drives_mask >>= 1;

        }

        for (int j = 0; j < s.size(); j++) {

            TCHAR ld[4];
            ld[0] = s[j];
            ld[1] = ':';
            ld[2] = '\\';
            ld[3] = '\0';

          	BOOL bFlag = GetVolumeInformation(ld, NULL, NULL, &SerialNumber, NULL, NULL, NULL, NULL);

				if (bFlag)			
				{					
					int p = 0;
					int count = 0;
				
						drive d = { 0 };
						d.name[0] = ld[0];
						memcpy(&d.SerialN, &SerialNumber, sizeof(SerialNumber));
						drives.push_back(d);
				}	

            }
    }



}

void checkFileSystem(byte type, char* code) {
	if (type == MBR_TYPE_NTFS)
		strcpy(code, "0x07");
	else if (type == MBR_TYPE_FAT32)
		strcpy(code, "0xOB");
	else if (type == MBR_TYPE_FAT32_LBA)
		strcpy(code, "0x0C");
	else
		strcpy(code, "NONE");
}



long int getSerialNumber(byte* boot, byte type) {    // в методичке этого не было, 
													 //найдено в интернете. Но я понимаю, как тут находится
													 //	серийный номер.		
	//получает результат от старшего бита к младшему
	long int serialNumber = 0;
	int start = 0;
	if (type == MBR_TYPE_NTFS) {
		start = 72;
	}
	else if (type == MBR_TYPE_FAT32 || type == MBR_TYPE_FAT32_LBA) {
		start = 67;
	}
	if (start != 0) {
		int count = 0;
		int end = start + 4;
		for (int j = start; j < end; j++) {
			serialNumber += (boot[j] << (8 * count));
			count++;
		}
	}
	return serialNumber;

}


void readPT(byte* buf) {
	for (int i = 0; i < 4; i++) {
		int count = 0;
		long int oa = 0;
		for (int j = 8; j < 12; j++) {
			oa += (buf[i * 16 + j + 446] << (8 * count));
			count++;
		}
		mbr_t.pt[i].otn_adr = oa;
		mbr_t.pt[i].type = buf[i * 16 + 4 + 446];
	}
}


BOOL ReadData(HANDLE hDevice, __int64 nAddr, void* pBuffer, unsigned long nBufferSize) {

	LARGE_INTEGER pos;
	pos.QuadPart = nAddr;
	unsigned long n;
	DWORD dRet = SetFilePointer(hDevice, pos.LowPart, &pos.HighPart, FILE_BEGIN);
	if ((dRet == 0xFFFFFFFF) && (GetLastError() != NO_ERROR)) {
		printf("Error SetFilePointer().\n");
		return FALSE;
	}

	BOOL bRet = ReadFile(hDevice, pBuffer, nBufferSize, &n, NULL);
	if (!bRet) {
		printf("Error reading.\n");
		return FALSE;
	}
	return TRUE;
}




int main() {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 0 << 4 | 9);
	BYTE MBR[LOGICAL_SECTOR_SIZE];
	BYTE boot[LOGICAL_SECTOR_SIZE];
	char num_device[25];
	char fs_code[15];
	CString code;

	scanDrives();										//найти те, что видны в Win

	for (int drive = 0; drive < 10; drive++) {

		snprintf(num_device, sizeof(num_device), "\\\\.\\PhysicalDrive%d", drive);
		HANDLE disk_h = CreateFileA(num_device, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (disk_h == INVALID_HANDLE_VALUE) continue;
		
		if (!ReadData(disk_h, 0, &MBR, sizeof(MBR))) {
			printf("Cannot to read this drive!\n");
			continue;
		}
		CloseHandle(disk_h);
		if ((MBR[510] != 0x55 && MBR[511] != 0xAA)) {
			printf("There is no 0x55AA signature!\n");
			continue;
		}

		
		printf("\n%s\n\n", num_device);

		readPT(MBR);

		if (mbr_t.pt[0].type == 0xEE || mbr_t.pt[0].type == 0xEF) {
			printf("Not mbr!\n");
			continue;
		}

		bool isExtended = false; 
		long long int beg_extended = 0;
		mbr_t.adr = 0;
		int i = 0;
		while (i < 4) {
			if (mbr_t.pt[i].type == 0x05 || mbr_t.pt[i].type == 0x0F) {					//если раздел расширенный
				
				beg_extended = mbr_t.pt[i].otn_adr * LOGICAL_SECTOR_SIZE; 	
				isExtended = true;
			
			}
			else if (mbr_t.pt[i].type != MBR_TYPE_UNUSED) {
				HANDLE disk_h = CreateFileA(num_device, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
				ReadData(disk_h, (mbr_t.pt[i].otn_adr + mbr_t.adr) * LOGICAL_SECTOR_SIZE, boot, sizeof(boot));
				CloseHandle(disk_h);
				
				
				mbr_t.pt[i].serialNumber = getSerialNumber(boot, mbr_t.pt[i].type);
				checkFileSystem(mbr_t.pt[i].type, fs_code);
			
				for (int j = 0; j < drives.size(); ++j) {
					if (drives[j].SerialN == mbr_t.pt[i].serialNumber) {			// сравнение с теми, что есть в Win
						std::cout << "\tLogical drive " << i << ":" << std::endl;
						std::cout << "\tFile system code: " << fs_code << std::endl;
						std::cout << "\tSerial number: " << std::hex << mbr_t.pt[i].serialNumber << std::endl << std::endl;
					}
				
				}
				
			}
			i++;
		}

		if (isExtended) {
			disk_h = CreateFileA(num_device, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			ReadData(disk_h, beg_extended, MBR, sizeof(MBR));
			CloseHandle(disk_h);

			if ((MBR[510] != 0x55 && MBR[511] != 0xAA)) {
				//продолжение работы, если сигнатура 55AA присутствует
				printf("There is no 0x55AA signature!\n");
				continue;
			}

			
			mbr_t.adr = beg_extended / LOGICAL_SECTOR_SIZE;
			readPT(MBR);

			long long int next_mbr;
			while (mbr_t.pt[1].type == 0x05 || mbr_t.pt[1].type == 0x0F) {
				for (int i = 0; i < 2; i++) {
					if (mbr_t.pt[i].type == 0x05 || mbr_t.pt[i].type == 0x0F) {
						next_mbr = beg_extended + mbr_t.pt[i].otn_adr * LOGICAL_SECTOR_SIZE;
					}
					else {
						HANDLE disk_h = CreateFileA(num_device, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
						ReadData(disk_h, (mbr_t.pt[i].otn_adr + mbr_t.adr) * LOGICAL_SECTOR_SIZE, boot, sizeof(boot));
						CloseHandle(disk_h);
						
						mbr_t.pt[i].serialNumber = getSerialNumber(boot, mbr_t.pt[i].type);
						checkFileSystem(mbr_t.pt[i].type, fs_code);


						code.Format(_T("0x%x"), mbr_t.pt[i].type);
						for (int j = 0; j < drives.size(); ++j) {
							if (drives[j].SerialN == mbr_t.pt[i].serialNumber) {// сравнение с теми, что есть в Win
								std::cout << "\tLogical drive " << i << ":" << std::endl;
								std::cout << "\tFile system code: " << fs_code << std::endl;
								std::cout << "\tSerial number: " << std::hex << mbr_t.pt[i].serialNumber << std::endl << std::endl;
							}

						}

					}
				}
				disk_h = CreateFileA(num_device, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
				ReadData(disk_h, next_mbr, MBR, sizeof(MBR));
				CloseHandle(disk_h);

				if ((MBR[510] != 0x55 && MBR[511] != 0xAA)) {
					//продолжение работы, если сигнатура 55AA присутствует
					printf("There is no 0x55AA signature!\n");
					continue;
				}

		
				mbr_t.adr = next_mbr / LOGICAL_SECTOR_SIZE;

				readPT(MBR);

			}
			i = 0;
			HANDLE disk_h = CreateFileA(num_device, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			ReadData(disk_h, (mbr_t.pt[i].otn_adr + mbr_t.adr) * LOGICAL_SECTOR_SIZE, boot, sizeof(boot));
			CloseHandle(disk_h);

			mbr_t.pt[i].serialNumber = getSerialNumber(boot, mbr_t.pt[i].type);
			checkFileSystem(mbr_t.pt[i].type, fs_code);
		
			code.Format(_T("0x%x"), mbr_t.pt[i].type);
			for (int j = 0; j < drives.size(); ++j) {
				if (drives[j].SerialN == mbr_t.pt[i].serialNumber) {// сравнение с теми, что есть в Win
					std::cout << "\tLogical drive " << i << ":" << std::endl;
					std::cout << "\tFile system code: " << fs_code << std::endl;
					std::cout << "\tSerial number: " << std::hex << mbr_t.pt[i].serialNumber << std::endl << std::endl;
				}


			}
		}
	}

	getchar();
	return 0;
}

