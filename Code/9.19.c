#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>

//函数声明
//**************************************************************************
//ReadPEFile:将文件读取到缓冲区
//参数说明：
//lpszFile 文件路径
//pFileBuffer 缓冲区指针
//返回值说明：
//读取失败返回0  否则返回实际读取的大小
//**************************************************************************
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer){
    //文件指针
    FILE* pfile = NULL;
    
    //打开文件，并将返回的FILE* 给创建的文件指针
    //判断pfile是否不为NULL
    if(!(pfile = fopen(lpszFile,"rb"))){
        printf("Can`t open the file!\n");
        exit(1);
    }

    //传入一个FILE* 指针 设置偏移为0 且指向文件末尾
    fseek(pfile,0,SEEK_END);

    //文件大小
    DWORD fileSize;
    //返回给定流的当前文件位置
    fileSize = ftell(pfile);
    // printf("This file is %d bytes!\n",fileSize); 

    //将文件指针设置到文件开头
    fseek(pfile,0,SEEK_SET);

    if(!(*pFileBuffer = malloc(fileSize))){
        printf("Can`t malloc filebuffer!\n");
        fclose(pfile);
        return 0;
    }
    printf("FileBuffer need malloc %d bytes\n",fileSize);

    //写入大小
    DWORD readSize;
    readSize = fread(*pFileBuffer,1,fileSize,pfile);
    if (!readSize){
        printf("Can`t copy file to buff!\n");
        fclose(pfile);
        return 0;
    }

    //关闭文件
    fclose(pfile);
    //返回写入Buff的大小
    return readSize;

}

//**************************************************************************
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer
//参数说明：
//pFileBuffer  FileBuffer指针
//pImageBuffer ImageBuffer指针
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;

    //将FileBuffer指向DOS头 
    pDh = (PIMAGE_DOS_HEADER)pFileBuffer;
    if(pDh->e_magic != IMAGE_DOS_SIGNATURE){
        printf("Not a valid PE file! Error by Dos header!\n");
        return 0;
    }

    //DOS头加上DOS头偏移找到NT头
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    //判断软件的IMAGE_NT_SIGNATURE
    if (pN32h->Signature != IMAGE_NT_SIGNATURE){
        printf("Not a valid PE file! Error by NT header!\n");
        return 0;
    }

    //指向PE头
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    printf("Size of OptionalHeader: %d\n",pFh->SizeOfOptionalHeader);
    printf("Size of sections: %d\n",pFh->NumberOfSections);
    //判断软件是64位还是32位
    // if (pFh->Machine == IMAGE_FILE_MACHINE_AMD64){
    //     pO64h = (PIMAGE_OPTIONAL_HEADER64)&(pN32h->OptionalHeader);
    //     DWORD Size_Image;
    //     Size_Image = pO64h->SizeOfImage;
    //     printf("SizeOfImage: %d",Size_Image);
    //     DWORD Size_Header;
    //     Size_Header = pO64h ->SizeOfHeaders;
    //     printf("SizeOfImage: %d",Size_Header);

    // }else if(pFh->Machine == IMAGE_FILE_MACHINE_I386){
    //     pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    //     DWORD Size_Image;
    //     Size_Image = pO32h->SizeOfImage;
    //     printf("SizeOfImage: %d",Size_Image);
    //     DWORD Size_Header;
    //     Size_Header = pO32h ->SizeOfHeaders;
    //     printf("SizeOfImage: %d",Size_Header);
    // }

    //指向另一个结构体-可选PE头
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    DWORD Size_Image;
    Size_Image = pO32h->SizeOfImage;
    printf("SizeOfImage: %d\n",Size_Image);
    DWORD Size_Header;
    Size_Header = pO32h ->SizeOfHeaders;
    printf("SizeOfHeaders: %d\n",Size_Header);

    if(!(*pImageBuffer = malloc(Size_Image * sizeof(char)))){
        printf("Can`t malloc ImageBuffer!\n");
        return 0;
    }

    //统计复制到pImageBuffer的大小
    DWORD Size_memcpy_Count = 0;
    memset(*pImageBuffer,0,Size_Image);
    memcpy(*pImageBuffer,pFileBuffer,Size_Header);
    Size_memcpy_Count += Size_Header;


    //循环读取pImageBuffer中已加载的节表的数据 并加载到pImageBuffer中
    //节表固定40(0x28)字节 节的数量为pFh->NumberOfSections
    for (int i = 0,j = 0; i < pFh->NumberOfSections; i++){
        //获取第i个节表在pImageBuffer中的位置
        pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader +j);
        printf("%d section of VirtualAddrs: 0x%x\n",i,pSh->VirtualAddress);
        printf("%d section of PointerToRawData: 0x%x\n",i,pSh->PointerToRawData);
        //memcpy需要两个void*类型的参数 使用LPVOID强制转换
        //Dst地址是将已申请的*pImageBuffer地址强转为DWORD64类型 *pImageBuffer为已申请的内存地址
        //再加上pSh->VirtualAddress 即为应在内存中的地址
        //VirtualAddress是该节在内存中的偏移
        //Src地址是将已加载到内存中的pFileBuffer的地址强转为DWORD64类型 并加上pSh->PointerToRawDate
        //PointerToRawDate是该节在文件中的偏移 即为该节在文件中的初始位置
        //需要复制的大小为pSh->SizeOfRawData 即为节在文件中对齐之后的尺寸
        memcpy((LPVOID)((DWORD64)(*pImageBuffer)+pSh->VirtualAddress),(LPVOID)((DWORD64)pFileBuffer+pSh->PointerToRawData),pSh->SizeOfRawData);
        Size_memcpy_Count += pSh->SizeOfRawData;
        j+=sizeof(IMAGE_SECTION_HEADER);
    }
    return Size_memcpy_Count;
}

//**************************************************************************
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区
//参数说明：
//pImageBuffer ImageBuffer指针
//pNewBuffer NewBuffer指针
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_last = NULL;

    pDh = (PIMAGE_DOS_HEADER)pImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    //*************************************************************
    //通过最后一个节的PointerToRawData(文件中偏移)+SizeOfRawData(对齐后在文件中的大小)
    //计算出NewBuffer所需要的大小
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    //计算最后一个节的地址
    pSh_last = pSh + (pFh->NumberOfSections-1);
    DWORD NewBuff_Size = pSh_last->PointerToRawData + pSh_last->SizeOfRawData;
    printf("pSh_last->PointerToRawData:%x\n",pSh_last->PointerToRawData);
    printf("pSh_last->SizeOfRawData:%x\n",pSh_last->SizeOfRawData);
    printf("Add:%x\n",pSh_last->SizeOfRawData + pSh_last->PointerToRawData);

    printf("NewBuffer Need: %d bytes\n",NewBuff_Size);
    //*************************************************************

    if(!(*pNewBuffer = malloc(NewBuff_Size * sizeof(char)))){
        printf("Can`t malloc NewBuffer!\n");
        return 0;
    }
    memset(*pNewBuffer,0,NewBuff_Size);
    
    //计算SizeOfHeaders 确定需要拷贝多少字节到NewBuffer
    DWORD Size_Header;
    Size_Header = pO32h ->SizeOfHeaders;
    printf("Size of Header: %d\n",Size_Header);
    //复制全部头和节表到NewBuffer
    memcpy(*pNewBuffer, pImageBuffer, Size_Header);
    //统计复制的文件大小
    DWORD Copy_Count = 0;
    Copy_Count += Size_Header;
    printf("Size_memcpy_Count: %d\n",Copy_Count);

    //循环复制节的数据到 Newbuffer
    for (size_t i = 0; i < pFh->NumberOfSections; i++){
        DWORD Size_Sections = pSh->SizeOfRawData;
        printf("%d Section of SizeOfRawData: %x\n",i,Size_Sections);
        memcpy((LPVOID)((DWORD64)*pNewBuffer + (pSh->PointerToRawData)), (LPVOID)((DWORD64)pImageBuffer + pSh->VirtualAddress), Size_Sections);
        Copy_Count += Size_Sections;
        printf("Copy_Count: %X\n",Copy_Count);
        pSh ++;
        
    }
    
    return Copy_Count;
}

//**************************************************************************
//MemeryTOFile:将内存中的数据复制到文件
//参数说明：
//pMemBuffer 内存中数据的指针
//size 要复制的大小
//lpszFile 要存储的文件路径
//返回值说明：
//读取失败返回0  否则返回复制的大小
//**************************************************************************
BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN DWORD Nsize,OUT LPSTR lpszFile){
    FILE* fp = NULL;
    if(!(fp = fopen(lpszFile,"wb"))){
        printf("Can`t open the File!\n");
        return 0;
    }
    DWORD Copy_Size = fwrite(pMemBuffer,1,Nsize,fp);
    if(!Copy_Size){
        printf("Can`t Write the File in MemeryTOFile!\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return Copy_Size;

}


//**************************************************************************
//RvaToFileOffset:将内存偏移转换为文件偏移
//参数说明：
//pFileBuffer FileBuffer指针
//dwRva RVA的值
//返回值说明：
//返回转换后的FOA的值  如果失败返回0
//**************************************************************************
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_last = NULL;

    pDh = (PIMAGE_DOS_HEADER)pFileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    
    DWORD NumOfSections = pFh->NumberOfSections;

    //PointerToRawData(文件中偏移) VirtualAddress(内存中偏移)
    //如果两者相等的话 说明对其方式是一样的 直接返回
    if(dwRva < pO32h->SizeOfHeaders || pO32h->SectionAlignment == pO32h->FileAlignment){
        // printf("SectionAlignment == FileAlignment\n");
        return dwRva;
    }

    DWORD FOA = 0;
    for (size_t i = 0; i < NumOfSections ; i++){
        if ((dwRva >= pSh->VirtualAddress) && (dwRva <(pSh->VirtualAddress + pSh->Misc.VirtualSize))){
            FOA = pSh->PointerToRawData + (dwRva - pSh->VirtualAddress);
            // printf("RAV to FOA is in %d Section = %x\n",i+1,FOA);
            break;
        }
        pSh ++;

    }
    return FOA;
}

//**************************************************************************
//FoaToRva:将文件偏移转换为内存偏移
//参数说明：
//pFileBuffer FileBuffer指针
//dwFoa FOA的值
//返回值说明：
//返回转换后的Rva的值  如果失败返回0
//**************************************************************************
DWORD FoaToRva(IN LPVOID pFileBuffer,IN DWORD dwFoa){
    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_last = NULL;

    pDh = (PIMAGE_DOS_HEADER)pFileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    
    DWORD NumOfSections = pFh->NumberOfSections;

    //PointerToRawData(文件中偏移) VirtualAddress(内存中偏移)
    //如果两者相等的话 说明对其方式是一样的 直接返回
    if(dwFoa < pO32h->SizeOfHeaders || pO32h->SectionAlignment == pO32h->FileAlignment){
        printf("SectionAlignment == FileAlignment\n");
        return dwFoa;
    }

    DWORD RVA = 0;
    for (size_t i = 0; i < NumOfSections ; i++){
        if ((dwFoa >= pSh->PointerToRawData ) && (dwFoa <=(pSh->PointerToRawData  + pSh->Misc.VirtualSize))){
            RVA = pSh->VirtualAddress + (dwFoa - pSh->PointerToRawData);
            // printf("RAV to FOA is in %d Section = %x\n",i+1,FOA);
            break;
        }
        pSh ++;

    }
    return RVA;
}

BOOL AddShellCode(){

    // SHellCode代码 执行一个弹窗
    BYTE ShellCode[] = {
    0x6a,0x00,0x6a,0x00,0x6a,0x00,0x6a,0x00,//8
    0xe8,0x00,0x00,0x00,0x00,//13
    0xe9,0x00,0x00,0x00,0x00,
    };

    //  BYTE ShellCode[] = {
    // 0xC7,0x44,0x24,0x0C,00,00,00,00,//8
    // 0xC7,0x44,0x24,0x08,00,00,00,00,//16
    // 0xC7,0x44,0x24,0x04,00,00,00,00,//24
    // 0xC7,0x44,0x24,00,00,00,00,00,//32
    // 0xe8,0x01,0x02,0x03,0x04,//37
    // 0xe9,0x05,0x06,0x07,0x08
    // };

    BYTE E8Bit = 0x9;    //修正E8指令的位置
    BYTE E9Bit = 0xe;    //修正E9指令位置
    BYTE E9addres = 0xd; //E8的下一条地址（E9）的位置

    PBYTE CodeBegin = NULL;

    //需要执行的MesagesBox在机器中的地址
    DWORD ProgrameAddress = 0x74E5A790;
    //ShellCode的长度
    DWORD Lenshellcode = sizeof(ShellCode);

    LPVOID FileBuffer = NULL;//FileBuffer
    LPVOID ImageBuffer = NULL;//ImageBuffer
    LPVOID NewBuffer = NULL;//NewBuffer


    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;


    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewBufferCopySize;
    DWORD WriteSize;
    
    //需要写入的文件和写入ShellCode之后的文件
    LPSTR InFilePath ="D:\\justdo\\A\\fg.exe";
    LPSTR OutFilePath = "D:\\justdo\\A\\fg_add.exe";

    //加载需要写入的文件
    FileSize = ReadPEFile(InFilePath,&FileBuffer);
    //将写入的文件拓展为内存中的状态
    FileCopySize = CopyFileBufferToImageBuffer(FileBuffer,&ImageBuffer);

    pDh = (PIMAGE_DOS_HEADER)ImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    //判断第一个节是否有空间能存下ShellCode的大小
    //文件中对齐之后的节的大小 - 内存中未对齐前的节的大小(内存中的实际大小)
    if ((pSh->SizeOfRawData - pSh->Misc.VirtualSize) < Lenshellcode){
        printf("Can`t enough write shellcode!\n");
        free(FileBuffer);
        free(ImageBuffer);
        return FALSE;
    }
    
    //第一个节在内存中最后的有数据的位置
    //内存中的位置 + 第一个节的偏移值 + 第一个节内存中未对齐前的大小
    CodeBegin = (PBYTE)((DWORD64)ImageBuffer + pSh->VirtualAddress + pSh->Misc.VirtualSize);

    printf("VirtualAddress: %x\n",pSh->VirtualAddress);
    printf("Misc.VirtualSize: %x\n",pSh->Misc.VirtualSize);
    printf("FileAlignment: %x\n",pO32h_Real->FileAlignment);
    printf("SectionAlignment: %x\n",pO32h_Real->SectionAlignment);
    printf("ImageBuffer_Address: %x\n",(DWORD64)ImageBuffer);
    printf("CodeBegin_Address: %x\n",CodeBegin);
    printf("CodeBegin_Address: %x\n",CodeBegin-(DWORD64)ImageBuffer);
    printf("ImageBase_Address: %x\n",pO32h_Real->ImageBase);
    printf("E8: %x\n",*(PDWORD)(CodeBegin + E8Bit));
    printf("E9: %x\n",*(PDWORD)(CodeBegin + E9Bit));
    printf("AddressOfEntryPoint: %x\n",pO32h->AddressOfEntryPoint);
    
    memcpy(CodeBegin,ShellCode,Lenshellcode);

    //修正E8
    //E8Call = 需要执行的程序的地址 - ImageBase(实际运行的时候的内存地址) + (ShellCode中E9的起始位置 - 内存中的位置)
    //E8Call = 需要执行的程序的地址 - ImageBase + E8Call在内存中的相对偏移
    DWORD E8Call = ProgrameAddress - (pO32h_Real->ImageBase + ((DWORD64)((CodeBegin + E9addres) -(DWORD64)ImageBuffer)));
    *(PDWORD)(CodeBegin + E8Bit) = E8Call;
    printf("E8Call:%x\n",E8Call);
    //修正E9
    DWORD E9Call = (pO32h_Real->ImageBase + pO32h->AddressOfEntryPoint) - (pO32h_Real->ImageBase + (DWORD64)((CodeBegin + Lenshellcode) - (DWORD64)ImageBuffer));
    *(PDWORD)(CodeBegin + E9Bit) = E9Call;
    printf("E9Call:%x\n",E9Call);
    //修正OEP
    pO32h->AddressOfEntryPoint = (DWORD64)CodeBegin - (DWORD64)ImageBuffer;

    NewBufferCopySize = CopyImageBufferToNewBuffer(ImageBuffer,&NewBuffer);

    WriteSize = MemeryTOFile(NewBuffer,NewBufferCopySize,OutFilePath);

    free(FileBuffer);
    free(ImageBuffer);
    free(NewBuffer);
    return TRUE;

}
//传入真实大小(relsize)和对齐大小(Alignment) 返回应该对齐的大小
DWORD getAlign(DWORD relsize, DWORD Alignment){
    return relsize/Alignment == relsize/(float)Alignment ? relsize: (relsize/Alignment+1)*Alignment;
}
//增加节
BOOL AddSection(){

    LPVOID FileBuffer = NULL;//FileBuffer
    LPVOID ImageBuffer = NULL;//ImageBuffer
    LPVOID NewBuffer = NULL;//NewBuffer
    //文件路径
    LPSTR FilePath ="D:\\Tools\\crack reverse\\TestFloder\\TraceMe.exe";
    LPSTR FileName = "D:\\Tools\\crack reverse\\TestFloder\\TraceMe_add.exe";

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;

    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewBufferCopySize;
    DWORD WriteSize;

    PBYTE tempbuff = NULL;
    //传入文件路径和void**类型的待申请地址空间
    FileSize = ReadPEFile(FilePath,&FileBuffer);
    FileCopySize = CopyFileBufferToImageBuffer(FileBuffer,&ImageBuffer);

    pDh = (PIMAGE_DOS_HEADER)ImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;

    //节的数量
    DWORD NumSecs = pFh->NumberOfSections;

    //节结束的位置 节表结束到第一个节空白区的开始位置
    pSh_new = pSh + NumSecs;
    //写入节表的可用空间
    DWORD Ablespace = pO32h_Real->SizeOfHeaders - ((DWORD64)pSh - (DWORD64)ImageBuffer);
    //判断尝试写入的空间够不够两个节表的空间
    if (Ablespace < (IMAGE_SIZEOF_SECTION_HEADER * 2)){
        printf("Can`t write Section!\n");
        free(FileBuffer);
        free(ImageBuffer);
        exit(1);
    }
    //将第一个节表的数据复制到新的位置上
    // memcpy((PBYTE)pSh_new,(PBYTE)pSh,IMAGE_SIZEOF_SECTION_HEADER);
    *pSh_new = *pSh;
    //将新增节表后面覆盖40个字节的0
    memset((pSh_new + 1),0,IMAGE_SIZEOF_SECTION_HEADER);
    //修改节表的名字
    BYTE NAME[IMAGE_SIZEOF_SHORT_NAME] = {".NewSec"};
    for (size_t i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++){
        pSh_new->Name[i] = NAME[i];
    }
    //修改节表的数量
    pFh->NumberOfSections += 1;
    
    //需要增加的节的大小
    DWORD AddSecSize = getAlign(0x4000,pO32h_Real->SectionAlignment);
    printf("AddSecSize: %x\n",AddSecSize);
    pO32h_Real->SizeOfImage += AddSecSize;
    //判断原始的最后一个节表中SizeOfRawData和VirtualSize谁大
    DWORD BigSize = (pSh_new-1)->SizeOfRawData >(pSh_new-1)->Misc.VirtualSize?(pSh_new-1)->SizeOfRawData:(pSh_new-1)->Misc.VirtualSize;
    //修改文件和内存偏移
    //修改文件大小和内存大小
    pSh_new->PointerToRawData = getAlign(BigSize + (pSh_new-1)->PointerToRawData,pO32h_Real->FileAlignment);
    pSh_new->VirtualAddress = getAlign(BigSize + (pSh_new-1)->VirtualAddress,pO32h_Real->SectionAlignment);
    pSh_new->Misc.VirtualSize = AddSecSize;
    pSh_new->SizeOfRawData = AddSecSize;

    //修改节属性
    pSh_new->Characteristics = 0xE00000C0;

    //重新分配内存
    ImageBuffer = realloc(ImageBuffer,pO32h_Real->SizeOfImage);
    memset(ImageBuffer + pO32h_Real->SizeOfImage - AddSecSize,0,AddSecSize);

    NewBufferCopySize = CopyImageBufferToNewBuffer(ImageBuffer,&NewBuffer);
    WriteSize = MemeryTOFile(NewBuffer,NewBufferCopySize,FileName);

    free(FileBuffer);
    free(ImageBuffer);
    free(NewBuffer);
    return TRUE;
}

//增加节 
//传入文件名和输出的文件名 以及文件需要被增加的大小
//返回增加的节的FOA
DWORD AddSection_Func(LPSTR filePath,LPSTR savePath ,DWORD adSize){

    LPVOID FileBuffer = NULL;//FileBuffer
    LPVOID ImageBuffer = NULL;//ImageBuffer
    LPVOID NewBuffer = NULL;//NewBuffer
    //文件路径
    LPSTR FilePath = filePath;
    LPSTR FileName = savePath;

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;

    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewBufferCopySize;
    DWORD WriteSize;

    PBYTE tempbuff = NULL;
    //传入文件路径和void**类型的待申请地址空间
    FileSize = ReadPEFile(FilePath,&FileBuffer);
    FileCopySize = CopyFileBufferToImageBuffer(FileBuffer,&ImageBuffer);

    pDh = (PIMAGE_DOS_HEADER)ImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;

    //节的数量
    DWORD NumSecs = pFh->NumberOfSections;

    //节结束的位置 节表结束到第一个节空白区的开始位置
    pSh_new = pSh + NumSecs;
    //写入节表的可用空间
    DWORD Ablespace = pO32h_Real->SizeOfHeaders - ((DWORD64)pSh_new - (DWORD64)ImageBuffer);
    //判断尝试写入的空间够不够两个节表的空间
    if (Ablespace < (IMAGE_SIZEOF_SECTION_HEADER * 2)){
        printf("Can`t write Section!\n");
        free(FileBuffer);
        free(ImageBuffer);
        exit(1);
    }
    //将第一个节表的数据复制到新的位置上
    // memcpy((PBYTE)pSh_new,(PBYTE)pSh,IMAGE_SIZEOF_SECTION_HEADER);
    *pSh_new = *pSh;
    //将新增节表后面覆盖40个字节的0
    memset((pSh_new + 1),0,IMAGE_SIZEOF_SECTION_HEADER);
    //修改节表的名字
    BYTE NAME[IMAGE_SIZEOF_SHORT_NAME] = {".NewSec"};
    for (size_t i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++){
        pSh_new->Name[i] = NAME[i];
    }
    //修改节表的数量
    pFh->NumberOfSections += 1;
    
    //需要增加的节的大小
    DWORD AddSecSize = getAlign(adSize,pO32h_Real->SectionAlignment);
    printf("AddSecSize: %x\n",AddSecSize);
    pO32h_Real->SizeOfImage += AddSecSize;
    //判断原始的最后一个节表中SizeOfRawData和VirtualSize谁大
    DWORD BigSize = (pSh_new-1)->SizeOfRawData >(pSh_new-1)->Misc.VirtualSize?(pSh_new-1)->SizeOfRawData:(pSh_new-1)->Misc.VirtualSize;
    //修改文件和内存偏移
    //修改文件大小和内存大小
    pSh_new->PointerToRawData = getAlign(BigSize + (pSh_new-1)->PointerToRawData,pO32h_Real->FileAlignment);
    pSh_new->VirtualAddress = getAlign(BigSize + (pSh_new-1)->VirtualAddress,pO32h_Real->SectionAlignment);
    pSh_new->Misc.VirtualSize = AddSecSize;
    pSh_new->SizeOfRawData = AddSecSize;

    //修改节属性
    pSh_new->Characteristics = 0xE00000C0;

    //重新分配内存
    ImageBuffer = realloc(ImageBuffer,pO32h_Real->SizeOfImage);
    //------------------------------尝试重新获取地址
    pDh = (PIMAGE_DOS_HEADER)ImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    memset(ImageBuffer + pO32h_Real->SizeOfImage - AddSecSize,0,AddSecSize);

    NewBufferCopySize = CopyImageBufferToNewBuffer(ImageBuffer,&NewBuffer);
    WriteSize = MemeryTOFile(NewBuffer,NewBufferCopySize,FileName);

    DWORD NewSecFoa = pSh_new->PointerToRawData;

    free(FileBuffer);
    free(ImageBuffer);
    free(NewBuffer);

    return NewSecFoa;
}

//扩大最后一个节
BOOL ExpandSection(){
    LPVOID FileBuffer = NULL;//FileBuffer
    LPVOID ImageBuffer = NULL;//ImageBuffer
    LPVOID NewBuffer = NULL;//NewBuffer
    //文件路径
    LPSTR FilePath = "D:\\justdo\\A\\fg.exe";
    LPSTR FileName = "D:\\justdo\\A\\fg_expand.exe";

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;

    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewBufferCopySize;
    DWORD WriteSize;

    //传入文件路径和void**类型的待申请地址空间
    FileSize = ReadPEFile(FilePath,&FileBuffer);
    FileCopySize = CopyFileBufferToImageBuffer(FileBuffer,&ImageBuffer);

    pDh = (PIMAGE_DOS_HEADER)ImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    
    //扩大最后一个节的大小
    DWORD ExpandSize = getAlign(0x2000,pO32h_Real->SectionAlignment);
    //节的数量
    DWORD NumSecs = pFh->NumberOfSections;
    //最后一个节表的数据
    pSh += (NumSecs -1);
    //判断原始的最后一个节表中SizeOfRawData和VirtualSize谁大
    DWORD BigSize = pSh->SizeOfRawData > pSh->Misc.VirtualSize?pSh->SizeOfRawData:pSh->Misc.VirtualSize;
    pSh->Misc.VirtualSize = getAlign(BigSize + ExpandSize,pO32h_Real->SectionAlignment);
    pSh->SizeOfRawData = getAlign(BigSize + ExpandSize,pO32h_Real->SectionAlignment);

    //修改空间大小
    pO32h->SizeOfImage += ExpandSize; 
    ImageBuffer = realloc(ImageBuffer,pO32h->SizeOfImage);
    memset(ImageBuffer + pO32h->SizeOfImage - ExpandSize,0,ExpandSize);

    NewBufferCopySize = CopyImageBufferToNewBuffer(ImageBuffer,&NewBuffer);
    WriteSize = MemeryTOFile(NewBuffer,NewBufferCopySize,FileName);

    free(FileBuffer);
    free(ImageBuffer);
    free(NewBuffer);
    return TRUE;
}

//合并节
BOOL MergeSection(){
    LPVOID FileBuffer = NULL;//FileBuffer
    LPVOID ImageBuffer = NULL;//ImageBuffer
    LPVOID NewBuffer = NULL;//NewBuffer
    //文件路径
    LPSTR FilePath = "D:\\justdo\\A\\massageBox32.exe";
    LPSTR FileName = "D:\\justdo\\A\\massageBox32_merge.exe";

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;

    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewBufferCopySize;
    DWORD WriteSize;

    //传入文件路径和void**类型的待申请地址空间
    FileSize = ReadPEFile(FilePath,&FileBuffer);
    FileCopySize = CopyFileBufferToImageBuffer(FileBuffer,&ImageBuffer);

    pDh = (PIMAGE_DOS_HEADER)ImageBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    
    //节的数量
    DWORD NumSecs = pFh->NumberOfSections;
    //最后一个节表的数据
    pSh += (NumSecs -1);
    //判断原始的最后一个节表中SizeOfRawData和VirtualSize谁大
    DWORD BigSize = pSh->SizeOfRawData > pSh->Misc.VirtualSize?pSh->SizeOfRawData:pSh->Misc.VirtualSize;
    //修改第一个节的VirtualSize和SizeOfRawData
    (pSh-(NumSecs-1))->Misc.VirtualSize = getAlign(pSh->VirtualAddress + BigSize - pO32h->SizeOfHeaders,pO32h_Real->SectionAlignment);
    (pSh-(NumSecs-1))->SizeOfRawData = getAlign(pSh->VirtualAddress + BigSize - pO32h->SizeOfHeaders,pO32h_Real->SectionAlignment);

    DWORD Chars = 0;
    for (size_t i = 0; i < NumSecs; i++){
        Chars |= (pSh-i)->Characteristics;
    }
    
    (pSh-(NumSecs-1))->Characteristics = Chars;

    pFh->NumberOfSections = 1;

    NewBufferCopySize = CopyImageBufferToNewBuffer(ImageBuffer,&NewBuffer);
    WriteSize = MemeryTOFile(NewBuffer,NewBufferCopySize,FileName);

    free(FileBuffer);
    free(ImageBuffer);
    free(NewBuffer);
    return TRUE;
}

//删除Doshub
void DelDosStub(){
    LPVOID FileBuffer = NULL;//FileBuffer
    DWORD FileSize;
    //文件路径
    LPSTR FilePath ="D:\\Tools\\crack reverse\\TestFloder\\ClickRun.exe";
    // LPSTR FilePath ="D:\\Tools\\crack reverse\\Hashyuan.exe";
    LPSTR FileName = "D:\\Tools\\crack reverse\\TestFloder\\ClickRun_delDosStub.exe";
    FileSize =  ReadPEFile(FilePath,&FileBuffer);

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_last = NULL;

    pDh = (PIMAGE_DOS_HEADER)FileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pSh_last = pSh + pFh->NumberOfSections;
    
    //Dos大小
    DWORD DosSize = sizeof(IMAGE_DOS_HEADER);
    //最后一个节的地址减去NT头的起始位置得到NT头到最后一个节的大小
    //实际需要复制的大小
    DWORD NtToSecL = (DWORD64)pSh_last- (DWORD64)pN32h;
    printf("Need Copy Size :%x\n",NtToSecL);
    //NT头的文件地址减去文件起始位置和DOS头大小得到DosStub的大小
    DWORD DosStubSize = (DWORD64)pN32h - (DWORD64)FileBuffer - DosSize;
    printf("DosStub Size :%x\n",DosStubSize);
    //从NT头开始复制NtToSecL个数据到DosStub的开始位置
    memcpy(FileBuffer + DosSize,pN32h,NtToSecL);
    //将剩余的原始数据覆盖为0
    memset(FileBuffer + DosSize + NtToSecL,0,DosStubSize);
    //修改e_lfanew位置
    pDh->e_lfanew = DosSize;
    
    MemeryTOFile(FileBuffer,FileSize,FileName);
    free(FileBuffer);
}

//打印导出表
void PrintOutDes(){

    LPVOID FileBuffer = NULL;//FileBuffer

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;
    PIMAGE_DATA_DIRECTORY pDd = NULL;
    PIMAGE_EXPORT_DIRECTORY pEd= NULL;

    
    // LPSTR FilePath = "D:\\Tools\\crack reverse\\TestFloder\\AdbWinApi.dll";
    LPSTR FilePath = "D:\\Tools\\crack reverse\\TestFloder\\AdbWinApi_export.dll";
    // LPSTR FilePath ="D:\\justdo\\A\\cearkTest\\libwinpthread-1.DLL";
    ReadPEFile(FilePath,&FileBuffer);

    pDh = (PIMAGE_DOS_HEADER)FileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    //数据目录表
    pDd = pO32h_Real->DataDirectory;
    //导出表的位置
    pEd = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,pDd->VirtualAddress));
    if (pDd->VirtualAddress == 0){
        printf("No Export Table!\n");
        return;
    }
    
    //数据目录
    printf("pEd VirtualAddress:%x\n",pDd->VirtualAddress);
    printf("pEd Size:%x\n",pDd->Size);
    //导出表
    printf("pEd->Characteristics:%x\n",pEd->Characteristics);
    printf("pEd->TimeDateStamp:%x\n",pEd->TimeDateStamp);
    printf("pEd->MajorVersion:%x\n",pEd->MajorVersion);
    printf("pEd->MinorVersion:%x\n",pEd->MinorVersion);
    printf("pEd->Name:%x\n",pEd->Name);
    printf("pEd->Base:%x\n",pEd->Base);
    printf("pEd->NumberOfFunctions:%x\n",pEd->NumberOfFunctions);
    printf("pEd->AddressOfNames:%x\n",pEd->NumberOfNames);
    printf("pEd->AddressOfFunctions:%x\n",pEd->AddressOfFunctions);
    printf("pEd->AddressOfNameOrdinals:%x\n",pEd->AddressOfNameOrdinals);
    printf("pEd->AddressOfNames:%x\n",pEd->AddressOfNames);
    
    //返回NumberOfFunctions和NumberOfNames中最大的
    DWORD max = pEd->NumberOfFunctions > pEd->NumberOfNames ? pEd->NumberOfFunctions:pEd->NumberOfNames;
    //将AddressOfFunctions的RVA转成FOA 加上 FileBuffer 得到数组在文件中的位置
    PDWORD aOf = (PDWORD)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer, pEd->AddressOfFunctions));
    //将AddressOfNameOrdinals的RVA转成FOA 加上 FileBuffer 得到数组在文件中的位置 该表中元素宽度为两字节
    PWORD aOo = (PWORD)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer, pEd->AddressOfNameOrdinals));
    //将AddressOfNames的RVA转成FOA 加上 FileBuffer 得到数组在文件中的位置
    PDWORD aOn = (PDWORD)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer, pEd->AddressOfNames));

    printf("No.|AOFunctions_RVA|AOFunctions_FOA|AONameOrdinals|AONames_RVA|AONames_FOA|AddressOfNames\n");
    for (size_t i = 0; i < max; i++){  
        printf("%3x", i); 
        if (i<pEd->NumberOfFunctions ){
            //RVA 实际AddressOfFunctions表中存的值
            printf("|%14x |",aOf[i]);
            //由于数组中存的也是RVA 所以还要再转成FOA 得到文件中的偏移
            printf("%14x |",RvaToFileOffset(FileBuffer,aOf[i]));
            //printf("%x\n", RvaToFileOffset(FileBuffer, ((PDWORD)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer, pEd->AddressOfFunctions)))[i]));
        }else{
            printf("|---------|");
        }
        if (i<pEd->NumberOfNames){
            //AddressOfNameOrdinals表中是值 直接输出
            printf("%13x |",aOo[i]);
            //AddressOfNames表中直接输出是名字的RVA
            printf("%10x |",aOn[i]);
            //AddressOfNames转换成FOA
            printf("%10x |",RvaToFileOffset(FileBuffer,aOn[i]));
            //获取真实名字在文件中的偏移(FOA)之后 加上FileBuffer的基地址 以字符串的方式输出
            printf("%s\n",(PSTR)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,aOn[i])));
        }
    }
    free(FileBuffer);
}

//打印重定位表
void PrintRelocatingDes(){

    LPVOID FileBuffer = NULL;//FileBuffer

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;
    PIMAGE_DATA_DIRECTORY pDd = NULL;
    PIMAGE_BASE_RELOCATION pBd= NULL;

    
    LPSTR FilePath = "D:\\Tools\\crack reverse\\TestFloder\\AdbWinApi_export_rel.dll";
    ReadPEFile(FilePath,&FileBuffer);

    pDh = (PIMAGE_DOS_HEADER)FileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    //数据目录表
    pDd = pO32h_Real->DataDirectory;
    printf("pDd rel Address:%x\n",(DWORD64)&(pDd->VirtualAddress) - (DWORD64)FileBuffer);
    //重定位表
    //数据目录的第六张表是重定位表
    // pDd = pDd[5].VirtualAddress;
    // pDd = pDd+5;
    printf("pDd->VirtualAddress:%x\n",pDd[5].VirtualAddress);
    printf("pDd->Size:%x\n",pDd[5].Size);
    //FileBuff位置 + 文件中偏移位置得到重定位表在文件中的位置
    pBd = (PIMAGE_BASE_RELOCATION)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,pDd[5].VirtualAddress));
    printf("RvaToFileOffset_BASE_RELOCATION:%x\n",RvaToFileOffset(FileBuffer,pDd[5].VirtualAddress));
    //************************************************************************************************************
    //输出全部
    DWORD count = 0;
    do{
        printf("%d VirtualAddress:%x SizeOfBlock:%x\n",count,pBd->VirtualAddress,pBd->SizeOfBlock);
        //Block的数量
        DWORD numBs = (pBd->SizeOfBlock-8)/2;
        //Block的地址
        PWORD pSb = (PWORD)((DWORD64)pBd + 8);
        // printf("pBd:%x\n",(DWORD64)pBd);
        // printf("pSb:%x\n",(DWORD64)pSb);
        for (size_t i = 0; i < numBs; i++){
            //判断高位是否为0 为0则不需要修改
            if (pSb[i]>>12 == 0) continue;
            //序号 block元素 block元素的文件偏移
            printf("%d %x %x\n",i,pSb[i],(DWORD64)&pSb[i] - (DWORD64)FileBuffer);
        }
        pBd = (PIMAGE_BASE_RELOCATION)((DWORD64)pBd+ pBd->SizeOfBlock);
        count++;
    } while (pBd->SizeOfBlock != 0 && pBd->VirtualAddress != 0 );
    // printf("pBd->VirtualAddress:%x\n",pBd->VirtualAddress);
    // printf("pBd->SizeOfBlock:%x\n",pBd->SizeOfBlock);
    //************************************************************************************************************
    free(FileBuffer);
}
//移动导出表
void Movexport(){

    LPVOID FileBuffer = NULL;//FileBuffer

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;
    PIMAGE_DATA_DIRECTORY pDd = NULL;
    PIMAGE_EXPORT_DIRECTORY pEd= NULL;
    PIMAGE_BASE_RELOCATION pBd= NULL;

    //文件路径
    LPSTR FilePath = "D:\\Tools\\crack reverse\\TestFloder\\AdbWinApi.dll";//原始文件
    LPSTR FileName = "D:\\Tools\\crack reverse\\TestFloder\\AdbWinApi_export.dll";//新增节后的文件
    DWORD adSize = 0x2000;

    //增加新的节 方便移动导出表和重定位表
    //NewSecFoa就是实际新增的节的PointerToRawData
    DWORD NewSecFoa = AddSection_Func(FilePath,FileName,adSize);
    printf("return FOA:%x\n",NewSecFoa);
    //将新增的节读取的内存中
    DWORD readSize = ReadPEFile(FileName,&FileBuffer);

    pDh = (PIMAGE_DOS_HEADER)FileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    //数据目录表
    pDd = pO32h_Real->DataDirectory;
    //导出表的位置
    pEd = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,pDd->VirtualAddress));
    //返回NumberOfFunctions和NumberOfNames中最大的
    DWORD max = pEd->NumberOfFunctions > pEd->NumberOfNames ? pEd->NumberOfFunctions:pEd->NumberOfNames;
    //将AddressOfFunctions的RVA转成FOA 加上 FileBuffer 得到数组在文件中的位置
    PDWORD aOf = (PDWORD)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer, pEd->AddressOfFunctions));
    //将AddressOfNameOrdinals的RVA转成FOA 加上 FileBuffer 得到数组在文件中的位置 该表中元素宽度为两字节
    PWORD aOo = (PWORD)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer, pEd->AddressOfNameOrdinals));
    //将AddressOfNames的RVA转成FOA 加上 FileBuffer 得到数组在文件中的位置
    PDWORD aOn = (PDWORD)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer, pEd->AddressOfNames));
    
    //复制将AddressOfFunctions表
    //新增加节在文件中的位置
    LPVOID NewSecAdd = FileBuffer + NewSecFoa;
    //AddressOfFunctions的大小 = NumberOfFunctions*4
    DWORD aOfSize = pEd->NumberOfFunctions * 4;
    printf("AddressOfFunctions Size:%x\n",aOfSize);
    memcpy(NewSecAdd,aOf,aOfSize);
    //复制AddressOfNameOrdinals
    //AddressOfNameOrdinals的大小 = NumberOfNames * 2
    DWORD aOoSize = pEd->NumberOfNames * 2;
    printf("AddressOfNameOrdinals Size:%x\n",aOoSize);
    memcpy(NewSecAdd + aOfSize,aOo,aOoSize);
    //复制AddressOfNames
    //AddressOfNames的大小 = NumberOfNames * 4
    DWORD aOnSize = pEd->NumberOfNames * 4;
    memcpy(NewSecAdd + aOfSize + aOoSize,aOn,aOnSize);
    printf("AddressOfNames Size:%x\n",aOnSize);
    //复制AddressOfNames实际的名称
    //真实名字在FileBuffer中的起始位置
   LPVOID aOnRelNamesStart = NewSecAdd + aOfSize + aOoSize + aOnSize;
   printf("Start address: %x\n",aOnRelNamesStart);
   for (size_t i = 0; i < pEd->NumberOfNames; i++){   
       //AddressOfNames表在文件中的位置
       PDWORD tempaOn = NewSecAdd + aOfSize + aOoSize;
       //依照原始的AddressOfNames表得到实际的函数名称 并且复制给一个临时变量temp
       PSTR temp = strcpy((PSTR)aOnRelNamesStart,(PSTR)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,aOn[i])));
       //字符串最后需要00结尾 所以要加一个字节
       DWORD tempSize = strlen(temp) + 1;
       //以下算出来是FOA 文件偏移
       //tempaOn[i] = (DWORD64)(temp - (DWORD64)FileBuffer);

       //实际需要转换成RVA再存入AddressOfNames表中 AddressOfNames表的修复
       tempaOn[i] = FoaToRva(FileBuffer,(DWORD64)(temp - (DWORD64)FileBuffer));

       //输出转换后的函数名 此时tempaOn等于aOn 保证解析的时候不出错
       //printf("%s\n",(PSTR)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,tempaOn[i])));
       
       //记录每次复制的字符串大小 为后续复制其他结构做基础
       aOnRelNamesStart += tempSize;
   }
    printf("Start address add all numbers of character: %x\n",aOnRelNamesStart);

    //复制导出表
    memcpy(aOnRelNamesStart,pEd,sizeof(IMAGE_EXPORT_DIRECTORY));

    //修改导出表里面三张表的位置
    //由于先复制了导出表 所以重新找到导出表的位置aOnRelNamesStart为再文件中的位置 已经加上了FileBuffer的值
    pEd = (PIMAGE_EXPORT_DIRECTORY)aOnRelNamesStart;
    //AddressOfFunctions、AddressOfNameOrdinals、AddressOfNames三张表的位置
    //实际存的值是RVA 所以需要转换 新增节的起始位置加上增加的数据大小就是各表的位置
    pEd->AddressOfFunctions = FoaToRva(FileBuffer,NewSecFoa);
    pEd->AddressOfNameOrdinals = FoaToRva(FileBuffer,NewSecFoa + aOfSize);
    pEd->AddressOfNames =FoaToRva(FileBuffer,NewSecFoa + aOfSize + aOoSize);


    //修复数据目录表第一项指向的值
    //数据目录表是在PE头中的 所以直接将复制之后的导出表的FOA转成RVA 然后修改就行了
    printf("original export address:%x\n",pDd->VirtualAddress);
    pDd->VirtualAddress = FoaToRva(FileBuffer,aOnRelNamesStart-FileBuffer);
    printf("Revised export address:%x\n",pDd->VirtualAddress);
    printf("Revised export`s FOA is:%x\n",RvaToFileOffset(FileBuffer,pDd->VirtualAddress));
    
    //将修改后的文件重新写入
    MemeryTOFile(FileBuffer,readSize,FileName);

    free(FileBuffer);
}
//传入一个文件 计算出的重定位表完整结构的大小
DWORD calcRelsize(LPSTR FilePath){

    LPVOID FileBuffer = NULL;//FileBuffer

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;
    PIMAGE_DATA_DIRECTORY pDd = NULL;
    PIMAGE_BASE_RELOCATION pBd= NULL;
    
    //首先将原始文件读入内存 做前期工作 取得重定位表大小
    ReadPEFile(FilePath,&FileBuffer);

    pDh = (PIMAGE_DOS_HEADER)FileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;
    //数据目录表
    pDd = pO32h_Real->DataDirectory;

    //重定位表在文件中的具体位置
    pBd = (PIMAGE_BASE_RELOCATION)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,pDd[5].VirtualAddress));
    //计算需要移动的重定位表的大小
    DWORD count = 0;
    //具体结构的大小
    do{
        //加上SizeOfBlock每个块的大小
        count += pBd->SizeOfBlock;
        //每次增加块的大小 移动到下一张表
        pBd = (PIMAGE_BASE_RELOCATION)((DWORD64)pBd+ pBd->SizeOfBlock);
    } while (pBd->SizeOfBlock != 0 && pBd->VirtualAddress != 0 );
    //要再加上8个字节的数据作为结尾
    count += 8;
    free(FileBuffer);
    return count;

}

//移动重定位表
//先将所有的块移动的新增节的位置 再移动重定位表表的位置
void MovRel(){

    LPVOID FileBuffer = NULL;//FileBuffer

    PIMAGE_DOS_HEADER pDh = NULL;
    PIMAGE_NT_HEADERS pN32h = NULL;
    PIMAGE_FILE_HEADER pFh = NULL;
    PIMAGE_OPTIONAL_HEADER pO32h = NULL;
    PIMAGE_OPTIONAL_HEADER32 pO32h_Real = NULL;
    PIMAGE_SECTION_HEADER pSh = NULL;
    PIMAGE_SECTION_HEADER pSh_new = NULL;
    PIMAGE_DATA_DIRECTORY pDd = NULL;
    PIMAGE_BASE_RELOCATION pBd= NULL;

    //文件路径
    LPSTR FilePath = "D:\\Tools\\crack reverse\\TestFloder\\AdbWinApi_export.dll";//原始文件
    LPSTR FileName = "D:\\Tools\\crack reverse\\TestFloder\\AdbWinApi_export_rel.dll";//新增节后的文件
    //计算重定位表所有块的大小 也是需要复制的大小
    DWORD count = calcRelsize(FilePath);
    //增加新的节的大小 方便移动重定位表 默认为0x4000
    DWORD adSize = 0x4000;
    printf("Need size of new sec:%x\n",count);
    adSize = count;
    //NewSecFoa就是实际新增的节的PointerToRawData
    DWORD NewSecFoa = AddSection_Func(FilePath,FileName,adSize);
    printf("return FOA:%x\n",NewSecFoa);

    //再将新增的节的文件读取的内存中
    DWORD ReadSize = ReadPEFile(FileName,&FileBuffer);

    pDh = (PIMAGE_DOS_HEADER)FileBuffer;
    pN32h = (PIMAGE_NT_HEADERS)((DWORD64)pDh + pDh->e_lfanew);
    pFh = (PIMAGE_FILE_HEADER)&(pN32h->FileHeader);
    pO32h = (PIMAGE_OPTIONAL_HEADER)&(pN32h->OptionalHeader);
    pSh = (PIMAGE_SECTION_HEADER)((DWORD64)&(pN32h->OptionalHeader) + pFh->SizeOfOptionalHeader);
    pO32h_Real = (PIMAGE_OPTIONAL_HEADER32)pO32h;

    //数据目录表
    pDd = pO32h_Real->DataDirectory;

    //FileBuff位置 + 文件中偏移位置得到重定位表在文件中的位置
    pBd = (PIMAGE_BASE_RELOCATION)((DWORD64)FileBuffer + RvaToFileOffset(FileBuffer,pDd[5].VirtualAddress));

    //开始复制块
    //新增节在文件中的位置
    LPVOID NewSecAdd = FileBuffer + NewSecFoa;
    memcpy(NewSecAdd,pBd,count);

    //修改重定位表所指向的位置 需要转换成RVA
    pDd[5].VirtualAddress = FoaToRva(FileBuffer,NewSecAdd - FileBuffer);
    printf("New file rel table in Foa:%x",RvaToFileOffset(FileBuffer,pDd[5].VirtualAddress));

    //将修改后的文件重新写入
    MemeryTOFile(FileBuffer,ReadSize,FileName);

    free(FileBuffer);
}

int fun(){
    LPVOID FileBuffer = NULL;//FileBuffer
    LPVOID ImageBuffer = NULL;//ImageBuffer
    LPVOID NewBuffer = NULL;//NewBuffer

    //文件路径
    LPSTR FilePath ="D:\\justdo\\A\\ClickRun.exe";
    // LPSTR FilePath ="D:\\Tools\\crack reverse\\Hashyuan.exe";
    LPSTR FileName = "D:\\justdo\\A\\ClickRun_Copy.exe";

    //返回的文件大小
    DWORD FileSize;
    DWORD FileCopySize;
    DWORD NewBufferCopySize;
    DWORD WriteSize;

    //传入文件路径和void**类型的待申请地址空间
    printf("*********************************************************\n");
    printf("ReadPEFile:\n");
    FileSize = ReadPEFile(FilePath,&FileBuffer);
    printf("Writed file to buffer %d betys\n",FileSize);
    printf("*********************************************************\n");
    printf("CopyFileBufferToImageBuffer:\n");
    FileCopySize = CopyFileBufferToImageBuffer(FileBuffer,&ImageBuffer);
    printf("Copy file to MemoryImage %d bytes\n",FileCopySize);
    printf("*********************************************************\n");
    printf("CopyImageBufferToNewBuffer:\n");
    NewBufferCopySize = CopyImageBufferToNewBuffer(ImageBuffer,&NewBuffer);
    printf("Copy ImageBuffer to NewBuffer %d bytes\n",NewBufferCopySize);
    printf("*********************************************************\n");
    printf("MemeryTOFile:\n");
    WriteSize = MemeryTOFile(NewBuffer,NewBufferCopySize,FileName);
    printf("Write NewBuffer to DiskFile %d bytes\n",WriteSize);
    printf("*********************************************************\n");

    free(FileBuffer);
    free(ImageBuffer);
    free(NewBuffer);
    return 0;
}

DWORD Test(){
    LPVOID FileBuffer = NULL;//FileBuffer
    // LPVOID ImageBuffer = NULL;//ImageBuffer
    // LPVOID NewBuffer = NULL;//NewBuffer

    //文件路径
    // LPSTR FilePath ="E:\\User\\Documents\\learn\\vs_learn\\C_Test\\word_test\\testod.exe";
    LPSTR FilePath ="D:\\justdo\\A\\websockets.dll";

    //返回的文件大小
    DWORD FileSize;
    // DWORD FileCopySize;
    // DWORD NewBufferCopySize;
    // DWORD WriteSize;
    printf("*********************************************************\n");
    printf("ReadPEFile:\n");
    FileSize = ReadPEFile(FilePath,&FileBuffer);
    printf("Writed file to buffer %d betys\n",FileSize);
    printf("*********************************************************\n");


    DWORD RAV =0x2378e0;
    DWORD FOA;
    FOA = RvaToFileOffset(FileBuffer,RAV);
    printf("FOA: %x",FOA);
    free(FileBuffer);

}

int main(int argc, char const *argv[])
{
    // fun();
    // Test();
    // AddShellCode();
    // AddSection();
    // DelDosStub();
    // ExpandSection();
    // MergeSection();
    // PrintOutDes();
    PrintRelocatingDes();
    // Movexport();
    // MovRel();
    return 0;
}
