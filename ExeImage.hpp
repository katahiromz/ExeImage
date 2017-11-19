// ExeImage.hpp
////////////////////////////////////////////////////////////////////////////

#ifndef EXE_IMAGE_HPP
#define EXE_IMAGE_HPP   4   // Version 4

#ifdef _WIN32
    #include <windows.h>
    #include <delayimp.h>       // ImgDelayDescr
#else
    #include "wonnt.h"
#endif

#include <vector>
#include <sstream>

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <sys/types.h>
#include <sys/stat.h>

namespace codereverse
{

struct ImportSymbol;
struct ExportSymbol;
class ExeImage;

////////////////////////////////////////////////////////////////////////////

struct ImportSymbol
{
    DWORD               iDLL;
    DWORD               dwRVA;
    WORD                wHint;
    union
    {
        struct
        {
            WORD        wImportByName;
            WORD        wOrdinal;
        } Name;
        const char     *pszName;
    };
};

////////////////////////////////////////////////////////////////////////////

struct ExportSymbol
{
    DWORD       dwRVA;
    DWORD       dwOrdinal;
    const char *pszName;
    const char *pszForwarded;
};

////////////////////////////////////////////////////////////////////////////

class ExeImage
{
public:
    ExeImage();
    ExeImage(const char *filename);
    ExeImage(const std::vector<BYTE>& image);
    virtual ~ExeImage();

    bool load(const char *filename);
    void unload();

    bool is_loaded();
    bool is_64bit();
    DWORD size_of_image();
    DWORD size_of_headers();
    DWORD number_of_sections();

    //
    // headers
    //
    IMAGE_DOS_HEADER *get_dos();
    IMAGE_NT_HEADERS32 *get_nt32();
    IMAGE_NT_HEADERS64 *get_nt64();
    IMAGE_NT_HEADERS *get_nt();
    IMAGE_OPTIONAL_HEADER32 *get_optional32();
    IMAGE_OPTIONAL_HEADER64 *get_optional64();
    IMAGE_OPTIONAL_HEADER *get_optional();

    //
    // data access
    //
    IMAGE_DATA_DIRECTORY *get_data_dir();
    IMAGE_DATA_DIRECTORY *get_data_dir(DWORD dwIndex);
    BYTE *get_data(DWORD dwIndex);
    BYTE *get_data(DWORD dwIndex, DWORD& dwSize);
    template <typename T_STRUCT>
    T_STRUCT *get_typed_data(DWORD dwIndex);

    bool rva_in_entry(DWORD rva, DWORD index) const;
    template <typename T_STRUCT>
    T_STRUCT *map_image(DWORD offset);
    template <typename T_STRUCT>
    T_STRUCT *map_file(DWORD offset);

    //
    // import
    //
    IMAGE_IMPORT_DESCRIPTOR *get_import();
    bool get_import_dll_names(std::vector<char *>& names);
    bool get_import_symbols(DWORD dll_index, std::vector<ImportSymbol>& symbols);

    //
    // export
    //
    IMAGE_EXPORT_DIRECTORY *get_export();
    bool get_export_symbols(std::vector<ExportSymbol>& symbols);

    //
    // delay load
    //
    ImgDelayDescr *get_delay_load();
    bool get_delay_load_entries(std::vector<ImgDelayDescr>& entries);

    //
    // resource
    //
    IMAGE_RESOURCE_DIRECTORY *get_resource();

    //
    // dumping
    //
    void dump_dos(std::stringstream& ss);
    void dump_nt(std::stringstream& ss);
    void dump_optional(std::stringstream& ss);
    void dump_data_dir(std::stringstream& ss);
    void dump_import(std::stringstream& ss);
    void dump_export(std::stringstream& ss);
    void dump_delay_load(std::stringstream& ss);

protected:
    std::string       m_filename;
    std::vector<BYTE> m_file_image;
    std::vector<BYTE> m_loaded_image;
    IMAGE_DOS_HEADER *m_dos;
    IMAGE_NT_HEADERS *m_nt;
    IMAGE_FILE_HEADER *m_file;
    IMAGE_SECTION_HEADER *m_section_table;
    IMAGE_DATA_DIRECTORY *m_data_dir;

    bool _do_map();
    void _get_import_symbols32(IMAGE_IMPORT_DESCRIPTOR *desc, std::vector<ImportSymbol>& symbols);
    void _get_import_symbols64(IMAGE_IMPORT_DESCRIPTOR *desc, std::vector<ImportSymbol>& symbols);
};

////////////////////////////////////////////////////////////////////////////
// inlines

inline ExeImage::ExeImage() :
    m_dos(NULL),
    m_nt(NULL),
    m_file(NULL),
    m_section_table(NULL),
    m_data_dir(NULL)
{
}

inline ExeImage::ExeImage(const char *filename) :
    m_dos(NULL),
    m_nt(NULL),
    m_file(NULL),
    m_section_table(NULL),
    m_data_dir(NULL)
{
    load(filename);
}

inline void ExeImage::unload()
{
    m_dos = NULL;
    m_nt = NULL;
    m_file = NULL;
    m_section_table = NULL;
    m_data_dir = NULL;
    m_file_image.clear();
    m_loaded_image.clear();
}

inline bool ExeImage::load(const char *filename)
{
    unload();

    using namespace std;
    struct stat st;
    if (stat(filename, &st) != 0)
        return false;

    bool ok = false;
    if (FILE *fp = fopen(filename, "rb"))
    {
        m_file_image.resize(st.st_size);
        if (fread(&m_file_image[0], st.st_size, 1, fp))
        {
            ok = true;
        }
        fclose(fp);
    }

    if (ok)
    {
        ok = _do_map();
    }
    if (ok)
    {
        m_filename = filename;
    }
    return ok;
}

inline ExeImage::~ExeImage()
{
}

inline bool ExeImage::_do_map()
{
    IMAGE_DOS_HEADER *dos = map_file<IMAGE_DOS_HEADER>(0);
    if (dos && dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew != 0)
    {
        m_dos = dos;
    }

    DWORD offset = dos ? dos->e_lfanew : 0;
    IMAGE_NT_HEADERS32 *nt32 = map_file<IMAGE_NT_HEADERS32>(offset);
    if (nt32 && nt32->Signature == IMAGE_NT_SIGNATURE)
    {
        m_nt = reinterpret_cast<IMAGE_NT_HEADERS *>(nt32);
        m_file = &m_nt->FileHeader;
    }
    else
    {
        return false;
    }

    if (IMAGE_NT_HEADERS64 *nt64 = get_nt64())
    {
        m_section_table = reinterpret_cast<IMAGE_SECTION_HEADER *>(nt64 + 1);
        m_data_dir = nt64->OptionalHeader.DataDirectory;
    }
    else
    {
        m_section_table = reinterpret_cast<IMAGE_SECTION_HEADER *>(nt32 + 1);
        m_data_dir = nt32->OptionalHeader.DataDirectory;
    }

    DWORD cbImage = size_of_image();
    DWORD cbHeaders = size_of_headers();
    m_loaded_image.resize(cbImage, 0);

    memcpy(&m_loaded_image[0], &m_file_image[0], cbHeaders);

    for (DWORD i = 0; i < m_file->NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER *entry = &m_section_table[i];
        if (entry->PointerToRawData)
        {
            memcpy(&m_loaded_image[entry->VirtualAddress],
                   &m_file_image[entry->PointerToRawData],
                   entry->SizeOfRawData);
        }
    }

    return true;
}

inline bool ExeImage::is_64bit()
{
    return get_nt64() != NULL;
}

inline IMAGE_DOS_HEADER *ExeImage::get_dos()
{
    if (m_dos && m_dos->e_magic == IMAGE_DOS_SIGNATURE && m_dos->e_lfanew != 0)
        return m_dos;
    return NULL;
}

inline IMAGE_NT_HEADERS32 *ExeImage::get_nt32()
{
    if (m_file && m_file->SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32))
        return reinterpret_cast<IMAGE_NT_HEADERS32 *>(m_nt);
    return NULL;
}

inline IMAGE_NT_HEADERS64 *ExeImage::get_nt64()
{
    if (m_file && m_file->SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
        return reinterpret_cast<IMAGE_NT_HEADERS64 *>(m_nt);
    return NULL;
}

inline IMAGE_NT_HEADERS *ExeImage::get_nt()
{
    if (m_file && m_file->SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER))
        return m_nt;
    return NULL;
}

inline IMAGE_OPTIONAL_HEADER32 *ExeImage::get_optional32()
{
    IMAGE_NT_HEADERS32 *nt32 = get_nt32();
    if (nt32)
        return &nt32->OptionalHeader;
    return NULL;
}

inline IMAGE_OPTIONAL_HEADER64 *ExeImage::get_optional64()
{
    if (IMAGE_NT_HEADERS64 *nt64 = get_nt64())
        return &nt64->OptionalHeader;
    return NULL;
}

inline IMAGE_OPTIONAL_HEADER *ExeImage::get_optional()
{
    if (IMAGE_NT_HEADERS *nt = get_nt())
        return &nt->OptionalHeader;
    return NULL;
}

inline DWORD ExeImage::size_of_headers()
{
    if (is_64bit())
        return get_optional64()->SizeOfHeaders;
    else
        return get_optional32()->SizeOfHeaders;
}

inline DWORD ExeImage::size_of_image()
{
    if (is_64bit())
        return get_optional64()->SizeOfImage;
    else
        return get_optional32()->SizeOfImage;
}

inline bool ExeImage::is_loaded()
{
    return m_nt != NULL;
}

inline DWORD ExeImage::number_of_sections()
{
    return m_file->NumberOfSections;
}

inline IMAGE_DATA_DIRECTORY *ExeImage::get_data_dir()
{
    return (is_loaded() ? m_data_dir : NULL);
}

inline IMAGE_DATA_DIRECTORY *ExeImage::get_data_dir(DWORD dwIndex)
{
    if (is_loaded() && m_data_dir)
    {
        if (0 <= dwIndex && dwIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
            return &m_data_dir[dwIndex];
    }
    return NULL;
}

inline BYTE *ExeImage::get_data(DWORD dwIndex)
{
    if (IMAGE_DATA_DIRECTORY *dir = get_data_dir(dwIndex))
    {
        if (dir->VirtualAddress && dir->Size)
        {
            return map_image<BYTE>(dir->VirtualAddress);
        }
    }
    return NULL;
}

inline BYTE *ExeImage::get_data(DWORD dwIndex, DWORD& dwSize)
{
    if (IMAGE_DATA_DIRECTORY *dir = get_data_dir(dwIndex))
    {
        if (dir->VirtualAddress && dir->Size)
        {
            dwSize = dir->Size;
            return map_image<BYTE>(dir->VirtualAddress);
        }
    }
    dwSize = 0;
    return NULL;
}

template <typename T_STRUCT>
inline T_STRUCT *ExeImage::get_typed_data(DWORD dwIndex)
{
    if (IMAGE_DATA_DIRECTORY *dir = get_data_dir(dwIndex))
    {
        if (dir->VirtualAddress && dir->Size)
        {
            return map_image<T_STRUCT>(dir->VirtualAddress);
        }
    }
    return NULL;
}

inline IMAGE_IMPORT_DESCRIPTOR *ExeImage::get_import()
{
    return get_typed_data<IMAGE_IMPORT_DESCRIPTOR>(IMAGE_DIRECTORY_ENTRY_IMPORT);
}

inline bool ExeImage::get_import_dll_names(std::vector<char *>& names)
{
    IMAGE_IMPORT_DESCRIPTOR *pImpDesc = get_import();
    if (!pImpDesc || !pImpDesc->OriginalFirstThunk)
        return false;

    for (; pImpDesc->FirstThunk != 0; ++pImpDesc)
    {
        names.push_back(map_image<char>(pImpDesc->Name));
    }
    return true;
}

inline bool ExeImage::get_import_symbols(DWORD dll_index, std::vector<ImportSymbol>& symbols)
{
    IMAGE_IMPORT_DESCRIPTOR *pImpDesc = get_import();
    if (!pImpDesc || !pImpDesc->OriginalFirstThunk)
        return false;

    if (is_64bit())
    {
        _get_import_symbols64(&pImpDesc[dll_index], symbols);
    }
    else
    {
        _get_import_symbols32(&pImpDesc[dll_index], symbols);
    }
    return true;
}

inline void
ExeImage::_get_import_symbols32(IMAGE_IMPORT_DESCRIPTOR *desc, std::vector<ImportSymbol>& symbols)
{
    IMAGE_IMPORT_BY_NAME *pIBN;
    DWORD *pIAT, *pINT;     // import address table & import name table

    pIAT = reinterpret_cast<DWORD *>(static_cast<DWORD_PTR>(desc->FirstThunk));
    if (desc->OriginalFirstThunk)
        pINT = reinterpret_cast<DWORD *>(map_image<BYTE>(desc->OriginalFirstThunk));
    else
        pINT = pIAT;

    for (DWORD k = 0; pINT[k] != 0; ++k)
    {
        if (pINT[k] >= size_of_image())
            continue;

        ImportSymbol symbol;
        symbol.dwRVA = desc->FirstThunk + k * sizeof(DWORD);

        if (IMAGE_SNAP_BY_ORDINAL32(pINT[k]))
        {
            symbol.wHint = 0;
            symbol.Name.wImportByName = 0;
            symbol.Name.wOrdinal = WORD(IMAGE_ORDINAL32(pINT[k]));
        }
        else
        {
            pIBN = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(map_image<BYTE>(pINT[k]));
            symbol.wHint = pIBN->Hint;
            symbol.pszName = reinterpret_cast<char *>(pIBN->Name);
        }

        symbols.push_back(symbol);
    }
}

inline void
ExeImage::_get_import_symbols64(IMAGE_IMPORT_DESCRIPTOR *desc, std::vector<ImportSymbol>& symbols)
{
    ULONGLONG *pIAT64, *pINT64;
    IMAGE_IMPORT_BY_NAME *pIBN;

    pIAT64 = reinterpret_cast<ULONGLONG *>(static_cast<DWORD_PTR>(desc->FirstThunk));
    if (desc->OriginalFirstThunk)
        pINT64 = map_image<ULONGLONG>(desc->OriginalFirstThunk);
    else
        pINT64 = pIAT64;

    for (DWORD k = 0; pINT64[k] != 0; ++k)
    {
        if (pINT64[k] >= size_of_image())
            continue;

        ImportSymbol symbol;
        symbol.dwRVA = desc->FirstThunk + k * sizeof(DWORD);

        if (IMAGE_SNAP_BY_ORDINAL64(pINT64[k]))
        {
            symbol.wHint = 0;
            symbol.Name.wImportByName = 0;
            symbol.Name.wOrdinal = WORD(IMAGE_ORDINAL64(pINT64[k]));
        }
        else
        {
            pIBN = map_image<IMAGE_IMPORT_BY_NAME>(DWORD(pINT64[k]));
            symbol.wHint = pIBN->Hint;
            symbol.pszName = reinterpret_cast<char *>(pIBN->Name);
        }

        symbols.push_back(symbol);
    }
}

inline IMAGE_EXPORT_DIRECTORY *ExeImage::get_export()
{
    return get_typed_data<IMAGE_EXPORT_DIRECTORY>(IMAGE_DIRECTORY_ENTRY_EXPORT);
}

inline bool ExeImage::get_export_symbols(std::vector<ExportSymbol>& symbols)
{
    IMAGE_EXPORT_DIRECTORY *dir = get_export();
    if (!dir)
        return false;

    // export address table (EAT)
    DWORD *pEAT = map_image<DWORD>(dir->AddressOfFunctions);
    // export name pointer table (ENPT)
    DWORD *pENPT = map_image<DWORD>(dir->AddressOfNames);
    // export ordinal table (EOT)
    WORD *pEOT = map_image<WORD>(dir->AddressOfNameOrdinals);

    DWORD i, k;
    WORD wOrdinal;
    for (i = 0; i < dir->NumberOfNames; ++i)
    {
        wOrdinal = pEOT[i];

        ExportSymbol symbol;
        symbol.dwRVA = pEAT[wOrdinal];
        symbol.pszName = map_image<char>(pENPT[i]);
        symbol.dwOrdinal = dir->Base + wOrdinal;
        symbol.pszForwarded = NULL;
        symbols.push_back(symbol);
    }

    for (i = 0; i < dir->NumberOfFunctions; ++i)
    {
        for (k = 0; k < dir->NumberOfNames; ++k)
        {
            if (static_cast<DWORD>(pEOT[k]) == i)
                break;
        }
        if (k < dir->NumberOfNames)
            continue;

        DWORD dw = pEAT[i];
        if (dw == 0)
            continue;

        ExportSymbol symbol;
        symbol.pszName = NULL;
        if (rva_in_entry(dw, IMAGE_DIRECTORY_ENTRY_EXPORT))
        {
            symbol.dwRVA = 0;
            symbol.pszForwarded = map_image<char>(dw);
        }
        else
        {
            symbol.dwRVA = dw;
            symbol.pszForwarded = NULL;
        }
        symbol.dwOrdinal = dir->Base + i;
        symbols.push_back(symbol);
    }

    return true;
}

inline ImgDelayDescr *ExeImage::get_delay_load()
{
    return get_typed_data<ImgDelayDescr>(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
}

inline bool ExeImage::get_delay_load_entries(std::vector<ImgDelayDescr>& entries)
{
    ImgDelayDescr *descr = get_delay_load();
    if (!descr || !descr->rvaHmod)
        return false;

    for (size_t i = 0; descr[i].rvaHmod; ++i)
    {
        entries.push_back(descr[i]);
    }
    return true;
}

inline IMAGE_RESOURCE_DIRECTORY *ExeImage::get_resource()
{
    return get_typed_data<IMAGE_RESOURCE_DIRECTORY>(IMAGE_DIRECTORY_ENTRY_RESOURCE);
}

inline bool ExeImage::rva_in_entry(DWORD rva, DWORD index) const
{
    assert(m_data_dir);
    return (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
            m_data_dir[index].VirtualAddress <= rva &&
            rva < m_data_dir[index].VirtualAddress + m_data_dir[index].Size);
}

template <typename T_STRUCT>
inline T_STRUCT *ExeImage::map_image(DWORD offset)
{
    if (m_loaded_image.size() < offset + sizeof(T_STRUCT))
        return NULL;
    BYTE *pb = reinterpret_cast<BYTE *>(&m_loaded_image[0]) + offset;
    return reinterpret_cast<T_STRUCT *>(pb);
}

template <typename T_STRUCT>
inline T_STRUCT *ExeImage::map_file(DWORD offset)
{
    if (m_file_image.size() < offset + sizeof(T_STRUCT))
        return NULL;
    BYTE *pb = reinterpret_cast<BYTE *>(&m_file_image[0]) + offset;
    return reinterpret_cast<T_STRUCT *>(pb);
}

////////////////////////////////////////////////////////////////////////////
// dumping

#define EXE_IMAGE_DUMP(ss,name,parent) ss << #name ": " << parent.name << "\n"
#define EXE_IMAGE_DUMP_PTR(ss,name,parent) ss << #name ": " << parent->name << "\n"

inline void ExeImage::dump_dos(std::stringstream& ss)
{
    ss << "\n### DOS Header ###\n";

    if (!m_dos)
    {
        ss << "No DOS header.\n";
        return;
    }

    EXE_IMAGE_DUMP_PTR(ss, e_magic, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_cblp, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_cp, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_crlc, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_cparhdr, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_minalloc, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_maxalloc, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_ss, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_sp, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_csum, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_ip, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_cs, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_lfarlc, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_ovno, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_oemid, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_oeminfo, m_dos);
    EXE_IMAGE_DUMP_PTR(ss, e_lfanew, m_dos);
}

inline void ExeImage::dump_nt(std::stringstream& ss)
{
    ss << "\n### NT Header ###\n";

    if (!m_nt)
    {
        ss << "Invalid NT header.\n";
        return;
    }

    if (is_64bit())
    {
        ss << "NT Header is 64-bit.\n";

        IMAGE_NT_HEADERS64 *nt64 = get_nt64();

        EXE_IMAGE_DUMP_PTR(ss, Signature, nt64);
        EXE_IMAGE_DUMP_PTR(ss, Machine, m_file);
        EXE_IMAGE_DUMP_PTR(ss, NumberOfSections, m_file);
        EXE_IMAGE_DUMP_PTR(ss, TimeDateStamp, m_file);
        EXE_IMAGE_DUMP_PTR(ss, PointerToSymbolTable, m_file);
        EXE_IMAGE_DUMP_PTR(ss, NumberOfSymbols, m_file);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfOptionalHeader, m_file);
        EXE_IMAGE_DUMP_PTR(ss, Characteristics, m_file);

        dump_optional(ss);
    }
    else
    {
        ss << "NT Header is 32-bit.\n";
        IMAGE_NT_HEADERS32 *nt32 = get_nt32();

        EXE_IMAGE_DUMP_PTR(ss, Signature, nt32);
        EXE_IMAGE_DUMP_PTR(ss, Machine, m_file);
        EXE_IMAGE_DUMP_PTR(ss, NumberOfSections, m_file);
        EXE_IMAGE_DUMP_PTR(ss, TimeDateStamp, m_file);
        EXE_IMAGE_DUMP_PTR(ss, PointerToSymbolTable, m_file);
        EXE_IMAGE_DUMP_PTR(ss, NumberOfSymbols, m_file);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfOptionalHeader, m_file);
        EXE_IMAGE_DUMP_PTR(ss, Characteristics, m_file);

        dump_optional(ss);
    }
}

inline void ExeImage::dump_optional(std::stringstream& ss)
{
    ss << "\n### Optional Header ###\n";

    if (is_64bit())
    {
        IMAGE_OPTIONAL_HEADER64 *optional64 = get_optional64();
        if (!optional64)
        {
            ss << "Invalid NT header.\n";
            return;
        }
        ss << "Optional Header is 64-bit.\n";

        EXE_IMAGE_DUMP_PTR(ss, Magic, optional64);
        ss << "MajorLinkerVersion: " << (UINT)optional64->MajorLinkerVersion << "\n";
        ss << "MinorLinkerVersion: " << (UINT)optional64->MinorLinkerVersion << "\n";
        EXE_IMAGE_DUMP_PTR(ss, SizeOfCode, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfInitializedData, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfUninitializedData, optional64);
        EXE_IMAGE_DUMP_PTR(ss, AddressOfEntryPoint, optional64);
        EXE_IMAGE_DUMP_PTR(ss, BaseOfCode, optional64);
        EXE_IMAGE_DUMP_PTR(ss, ImageBase, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SectionAlignment, optional64);
        EXE_IMAGE_DUMP_PTR(ss, FileAlignment, optional64);
        EXE_IMAGE_DUMP_PTR(ss, MajorOperatingSystemVersion, optional64);
        EXE_IMAGE_DUMP_PTR(ss, MinorOperatingSystemVersion, optional64);
        EXE_IMAGE_DUMP_PTR(ss, MajorImageVersion, optional64);
        EXE_IMAGE_DUMP_PTR(ss, MinorImageVersion, optional64);
        EXE_IMAGE_DUMP_PTR(ss, MajorSubsystemVersion, optional64);
        EXE_IMAGE_DUMP_PTR(ss, MinorSubsystemVersion, optional64);
        EXE_IMAGE_DUMP_PTR(ss, Win32VersionValue, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfImage, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfHeaders, optional64);
        EXE_IMAGE_DUMP_PTR(ss, CheckSum, optional64);
        EXE_IMAGE_DUMP_PTR(ss, Subsystem, optional64);
        EXE_IMAGE_DUMP_PTR(ss, DllCharacteristics, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfStackReserve, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfStackCommit, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfHeapReserve, optional64);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfHeapCommit, optional64);
        EXE_IMAGE_DUMP_PTR(ss, LoaderFlags, optional64);
        EXE_IMAGE_DUMP_PTR(ss, NumberOfRvaAndSizes, optional64);
    }
    else
    {
        IMAGE_OPTIONAL_HEADER32 *optional32 = get_optional32();
        if (!optional32)
        {
            ss << "Invalid NT header.\n";
            return;
        }
        ss << "Optional Header is 32-bit.\n";

        EXE_IMAGE_DUMP_PTR(ss, Magic, optional32);
        ss << "MajorLinkerVersion: " << (UINT)optional32->MajorLinkerVersion << "\n";
        ss << "MinorLinkerVersion: " << (UINT)optional32->MinorLinkerVersion << "\n";
        EXE_IMAGE_DUMP_PTR(ss, SizeOfCode, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfInitializedData, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfUninitializedData, optional32);
        EXE_IMAGE_DUMP_PTR(ss, AddressOfEntryPoint, optional32);
        EXE_IMAGE_DUMP_PTR(ss, BaseOfCode, optional32);
        EXE_IMAGE_DUMP_PTR(ss, BaseOfData, optional32);
        EXE_IMAGE_DUMP_PTR(ss, ImageBase, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SectionAlignment, optional32);
        EXE_IMAGE_DUMP_PTR(ss, FileAlignment, optional32);
        EXE_IMAGE_DUMP_PTR(ss, MajorOperatingSystemVersion, optional32);
        EXE_IMAGE_DUMP_PTR(ss, MinorOperatingSystemVersion, optional32);
        EXE_IMAGE_DUMP_PTR(ss, MajorImageVersion, optional32);
        EXE_IMAGE_DUMP_PTR(ss, MinorImageVersion, optional32);
        EXE_IMAGE_DUMP_PTR(ss, MajorSubsystemVersion, optional32);
        EXE_IMAGE_DUMP_PTR(ss, MinorSubsystemVersion, optional32);
        EXE_IMAGE_DUMP_PTR(ss, Win32VersionValue, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfImage, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfHeaders, optional32);
        EXE_IMAGE_DUMP_PTR(ss, CheckSum, optional32);
        EXE_IMAGE_DUMP_PTR(ss, Subsystem, optional32);
        EXE_IMAGE_DUMP_PTR(ss, DllCharacteristics, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfStackReserve, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfStackCommit, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfHeapReserve, optional32);
        EXE_IMAGE_DUMP_PTR(ss, SizeOfHeapCommit, optional32);
        EXE_IMAGE_DUMP_PTR(ss, LoaderFlags, optional32);
        EXE_IMAGE_DUMP_PTR(ss, NumberOfRvaAndSizes, optional32);
    }

    dump_data_dir(ss);
}

inline void ExeImage::dump_data_dir(std::stringstream& ss)
{
    ss << "\n### Data Directories ###\n";

    IMAGE_DATA_DIRECTORY *dir = get_data_dir();
    if (!dir)
    {
        ss << "No data directories.\n";
        return;
    }

    for (DWORD dwIndex = 0; dwIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++dwIndex)
    {
        ss << "#" << dwIndex << ": VirtualAddress " << dir->VirtualAddress <<
              ", Size " << dir->Size << ".\n";
        ++dir;
    }
}

inline void ExeImage::dump_import(std::stringstream& ss)
{
    ss << "\n### Import ###\n";

    std::vector<char *> names;
    if (!get_import_dll_names(names))
    {
        ss << "No import table.\n";
        return;
    }

    for (size_t i = 0; i < names.size(); ++i)
    {
        ss << names[i] << ": \n";
        std::vector<ImportSymbol> symbols;
        if (get_import_symbols(i, symbols))
        {
            for (size_t k = 0; k < symbols.size(); ++k)
            {
                ImportSymbol& symbol = symbols[k];
                if (symbol.Name.wImportByName)
                {
                    ss << "    " << symbol.pszName << " (hint: " << symbol.wHint << ")\n";
                }
                else
                {
                    ss << "    @" << symbol.Name.wOrdinal << "\n";
                }
            }
        }
    }
}

inline void ExeImage::dump_export(std::stringstream& ss)
{
    ss << "\n### Export ###\n";

    std::vector<ExportSymbol> symbols;
    if (!get_export_symbols(symbols))
    {
        ss << "No export table.\n";
        return;
    }

    for (size_t i = 0; i < symbols.size(); ++i)
    {
        ExportSymbol& symbol = symbols[i];

        if (symbol.pszName)
            ss << "    " << symbol.pszName << ": " << symbol.dwOrdinal << "\n";
        else
            ss << "    (no name): " << symbol.dwOrdinal << "\n";
    }
}

inline void ExeImage::dump_delay_load(std::stringstream& ss)
{
    ss << "\n### Delay Load ###\n";

    std::vector<ImgDelayDescr> entries;
    if (!get_delay_load_entries(entries))
    {
        ss << "No delay load.\n";
        return;
    }

    for (size_t i = 0; i < entries.size(); ++i)
    {
        ss << "Entry #" << i << "\n";
        EXE_IMAGE_DUMP(ss, grAttrs, entries[i]);
        EXE_IMAGE_DUMP(ss, rvaDLLName, entries[i]);
        EXE_IMAGE_DUMP(ss, rvaHmod, entries[i]);
        EXE_IMAGE_DUMP(ss, rvaIAT, entries[i]);
        EXE_IMAGE_DUMP(ss, rvaINT, entries[i]);
        EXE_IMAGE_DUMP(ss, rvaBoundIAT, entries[i]);
        EXE_IMAGE_DUMP(ss, rvaUnloadIAT, entries[i]);
        EXE_IMAGE_DUMP(ss, dwTimeStamp, entries[i]);
    }
}

////////////////////////////////////////////////////////////////////////////

#undef EXE_IMAGE_DUMP
#undef EXE_IMAGE_DUMP_PTR

} // namespace codereverse

#endif  // ndef EXE_IMAGE_HPP
