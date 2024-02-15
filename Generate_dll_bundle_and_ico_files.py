import os
import struct
import mmap
from PIL import Image

__all__ = [ 'PeResourceDllFromIconFiles', 'IconFile', 'ico2dll' ]

SECTION_ALIGNMENT = 4096
FILE_ALIGNMENT = 512
HEADER_SIZE = 512
RSRC_SECTIONVA = 4096

# Function to pad size to a given alignment
def _pad_size_to(size, alignment):
    if size % alignment != 0:
        size += alignment - size % alignment

    assert size % alignment == 0
    return size

# Function to fix PE checksum
def _fix_pe_checksum(pebytes):
    # calculate signature offset
    ohoff, = struct.unpack('<L', pebytes[0x3c:0x40])
    checksumoff = ohoff + 88

    # reset existing checksum in file
    pebytes[checksumoff:checksumoff+4] = b'\0\0\0\0'

    # compute the new checksum
    s = 0
    for i in range(0, len(pebytes), 2):
        v, = struct.unpack('<H', pebytes[i:i+2])

        s = (s + v) & 0xffffffff
        s = ((s >> 16) + (s & 0xffff)) & 0xffffffff

    s = (s + len(pebytes)) & 0xffffffff

    # write new checksum into file
    pebytes[checksumoff:checksumoff+4] = struct.pack('<L', s)

# PeResourceDirectoryEntry class
class PeResourceDirectoryEntry:
    def __init__(self, databytes, codepage):
        self.data = databytes
        self.codepage = codepage

    def as_bytes(self, offset_in_section, sectionva):
        r = bytearray()
        r += struct.pack('<LLLL',
                         sectionva + offset_in_section + 16,
                         len(self.data),
                         self.codepage,
                         0)
        r += self.data
        if len(r) % 4 != 0:
            r += b'\0' * (4 - len(r) % 4)

        return r

# PeResourceDirectoryTable class
class PeResourceDirectoryTable:
    def __init__(self):
        self.characteristics = 0
        self.timestamp = 0
        self.majorversion = 0
        self.minorversion = 0
        self.entries = dict() # Dict[id, Union[PeResourceDirectoryTable, PeResourceDirectoryEntry]]

    def as_bytes(self, offset_in_section, sectionva):
        h = bytearray()

        h += struct.pack('<LLHHHH',
                         self.characteristics,
                         self.timestamp,
                         self.majorversion,
                         self.minorversion,
                         0,
                         len(self.entries))

        dataoff = offset_in_section + len(h) + len(self.entries) * 8

        d = bytearray()

        for id, content in self.entries.items():
            o = dataoff + len(d)
            if isinstance(content, PeResourceDirectoryTable):
                o |= 0x80000000
            h += struct.pack('<LL', id, o)
            d += content.as_bytes(dataoff + len(d), sectionva)

        return h + d

# PeResourceSectionBuilder class
class PeResourceSectionBuilder:
    def __init__(self):
        self.rootdir = PeResourceDirectoryTable()

    def as_bytes(self, sectionva):
        return self.rootdir.as_bytes(0, sectionva)

    def add_resource(self, type, id, language, codepage, data):
        if type in self.rootdir.entries:
            typedir = self.rootdir.entries[type]
        else:
            typedir = PeResourceDirectoryTable()
            self.rootdir.entries[type] = typedir

        if id in typedir.entries:
            iddir = typedir.entries[id]
        else:
            iddir = PeResourceDirectoryTable()
            typedir.entries[id] = iddir

        iddir.entries[language] = PeResourceDirectoryEntry(data, codepage)

# GrpIconDirEntry class
class GrpIconDirEntry:
    def __init__(self, icoentry, dataid):
        self.width = icoentry.width
        self.height = icoentry.height
        self.colorcount = icoentry.colorcount
        self.reserved = icoentry.reserved
        self.planes = icoentry.planes
        self.bitcount = icoentry.bitcount
        self.bytesinres = len(icoentry.data)
        self.id = dataid

    def as_bytes(self):
        return struct.pack('<BBBBHHLH',
                           self.width,
                           self.height,
                           self.colorcount,
                           self.reserved,
                           self.planes,
                           self.bitcount,
                           self.bytesinres,
                           self.id)

# GrpIconDirBuilder class
class GrpIconDirBuilder:
    def __init__(self):
        self.entries = []

    def add_entry(self, icoentry, id):
        self.entries.append(GrpIconDirEntry(icoentry, id))

    def as_bytes(self):
        r = bytearray()

        r += struct.pack('<HHH',
                         0, 1, len(self.entries))

        for e in self.entries:
            r += e.as_bytes()

        return r

# IconDirEntry class
class IconDirEntry:
    def __init__(self, data, offset):
        self.width, \
        self.height, \
        self.colorcount, \
        self.reserved, \
        self.planes, \
        self.bitcount, \
        bytesinres, imageoffset = \
            struct.unpack('<BBBBHHLL', data[offset:offset+16])

        self.data = data[imageoffset:imageoffset+bytesinres]

# IconFile class
class IconFile:
    def __init__(self, f):
        self.type = 0
        self.entries = []

        if hasattr(f, 'fileno'):
            # already opened file
            self._load_from_file(f)
        else:
            # filename or path object or whatever
            with open(f, 'rb') as f:
                self._load_from_file(f)

    def _load_from_file(self, f):
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            reserved, self.type, count = \
                struct.unpack('<HHH', m[0:6])

            assert reserved == 0
            assert self.type == 1

            for i in range(0, count):
                self.entries.append(IconDirEntry(m, 6 + i *16))

# PeResourceDllFromRsrcBytes function
def PeResourceDllFromRsrcBytes(rsrcbytes, rsrcva):
    r = bytearray()

    # dos stub - only relevant part is the offset of the PE header
    # we could remove everything else, but it wouldn't buy us any space
    # since the .rsrc section needs to be aligned to FILE_ALIGNMENT anyway
    r += b'\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00'
    r += b'\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
    r += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    r += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00'
    r += b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x54\x68'
    r += b'\x69\x73\x20\x70\x72\x6F\x67\x72\x61\x6D\x20\x63\x61\x6E\x6E\x6F'
    r += b'\x74\x20\x62\x65\x20\x72\x75\x6E\x20\x69\x6E\x20\x44\x4F\x53\x20'
    r += b'\x6D\x6F\x64\x65\x2E\x0D\x0D\x0A\x24\x00\x00\x00\x00\x00\x00\x00'

    # pe signature
    r += b'PE\0\0'

    # COFF HEADER
    r += struct.pack('<H', 0x14c) # IMAGE_FILE_MACHINE_I386
    r += struct.pack('<H', 1) # number of sections
    r += b'\0\0\0\0' # TODO: time date stamp
    r += b'\0\0\0\0' # pointer to symbol table
    r += b'\0\0\0\0' # number of symbols
    r += struct.pack('<H', 224) # size of optional header
    r += struct.pack('<H', 0x230e) # characteristics

    # PE Optional Header
    r += struct.pack('<H', 0x10b) # magic
    r += b'\0\0'     # linker version
    r += b'\0\0\0\0' # size of code
    r += b'\0\0\0\0' # size of initialized data
    r += b'\0\0\0\0' # size of uninitialized data
    r += b'\0\0\0\0' # address of entry point
    r += b'\0\0\0\0' # base of code
    r += b'\0\0\0\0' # base of data

    r += struct.pack('<L', 0x10000000) # image base
    r += struct.pack('<L', SECTION_ALIGNMENT) # section alignment
    r += struct.pack('<L', FILE_ALIGNMENT) # file alignment
    r += b'\x04\0\0\0' # OS version
    r += b'\x01\0\0\0' # image version
    r += b'\x04\0\0\0' # subsystem version
    r += b'\0\0\0\0' # reserved
    r += struct.pack('<L', _pad_size_to(rsrcva + len(rsrcbytes), SECTION_ALIGNMENT)) # size of image in memory
    r += struct.pack('<L', HEADER_SIZE) # size of headers in file
    r += b'\0\0\0\0' # checksum, will be fixed later
    r += b'\x02\0' # subsystem IMAGE_SUBSYSTEM_WINDOWS_GUI
    r += b'\0\0' # dll characteristics
    r += b'\0\0\x20\0' # size of stack reserve
    r += b'\0\x10\0\0' # size of stack commit
    r += b'\0\0\x10\0' # size of heap reserve
    r += b'\0\x10\0\0' # size of heap commit
    r += b'\0\0\0\0' # reserved
    r += b'\x10\0\0\0' # number of RvaAndSizes, we use all 16

    # PE Data directories
    r += b'\0\0\0\0\0\0\0\0' # export table
    r += b'\0\0\0\0\0\0\0\0' # import table
    r += struct.pack('<LL', rsrcva, len(rsrcbytes)) # resource table
    r += b'\0\0\0\0\0\0\0\0' # exception table
    r += b'\0\0\0\0\0\0\0\0' # certificate table
    r += b'\0\0\0\0\0\0\0\0' # base relocation table
    r += b'\0\0\0\0\0\0\0\0' # debug
    r += b'\0\0\0\0\0\0\0\0' # reserved
    r += b'\0\0\0\0\0\0\0\0' # global ptr
    r += b'\0\0\0\0\0\0\0\0' # tls table
    r += b'\0\0\0\0\0\0\0\0' # load config table
    r += b'\0\0\0\0\0\0\0\0' # bound import
    r += b'\0\0\0\0\0\0\0\0' # import address table
    r += b'\0\0\0\0\0\0\0\0' # delay import descriptor
    r += b'\0\0\0\0\0\0\0\0' # clr runtime header
    r += b'\0\0\0\0\0\0\0\0' # reserved

    # Section Table
    # we only have one rsrc section
    r += b'.rsrc\0\0\0' # section name
    r += struct.pack('<L', _pad_size_to(len(rsrcbytes), SECTION_ALIGNMENT))
    r += struct.pack('<L', rsrcva) # virtual address
    r += struct.pack('<L', len(rsrcbytes)) # size of raw data
    r += struct.pack('<L', HEADER_SIZE) # pointer to raw data
    r += b'\0\0\0\0' # pointer to relocations
    r += b'\0\0\0\0' # pointer to line numbers
    r += b'\0\0' # number of relocations
    r += b'\0\0' # number of line numbers
    r += struct.pack('<L', 0xc0300040) # section flags: IMAGE_SCN_MEM_WRITE | IMANGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_CNT_INITIALIZED_DATA

    # pad to header size
    assert len(r) <= HEADER_SIZE
    r += b'\0' * (HEADER_SIZE - len(r))

    # section data for rsrc section
    r += rsrcbytes

    # pad to file alignment
    if len(r) % FILE_ALIGNMENT != 0:
        r += b'\0' * (FILE_ALIGNMENT - len(r) % FILE_ALIGNMENT)

    _fix_pe_checksum(r)

    return r

# Function to convert icon files to DLL
def PeResourceDllFromIconFiles(icofiles):
    rsrcbuilder = PeResourceSectionBuilder()

    icocounter = 1
    grpcounter = 1

    for icodata in icofiles:
        grpbuilder = GrpIconDirBuilder()

        for e in icodata.entries:
            rsrcbuilder.add_resource(3, icocounter, 1033, 0, e.data)
            grpbuilder.add_entry(e, icocounter)

            icocounter += 1

        rsrcbuilder.add_resource(14, grpcounter, 1033, 0, grpbuilder.as_bytes())
        grpcounter += 1

    return PeResourceDllFromRsrcBytes(rsrcbuilder.as_bytes(RSRC_SECTIONVA), RSRC_SECTIONVA)

# Function to convert icon files to DLL
def ico_to_dll(ico_files):
    icon_instances = [IconFile(file_path) for file_path in ico_files]
    return PeResourceDllFromIconFiles(icon_instances)

def main():
    # Get current directory
    current_directory = os.getcwd()

    # Iterate over folders
    for folder_name in os.listdir(current_directory):
        if folder_name == "ScanBypass": continue
        folder_path = os.path.join(current_directory, folder_name)

        # Skip if not a directory
        if not os.path.isdir(folder_path):
            continue

        # Get all the image files from the folder
        image_files = []
        for root, dir, files in os.walk(folder_path):
            for file in files:
                if file.endswith((".jpg", ".jpeg", ".png", ".bmp")):
                    image_files.append(os.path.join(root, file))

        # Convert images to ICO format
        ico_files = []
        for i, image_path in enumerate(image_files):
            with Image.open(image_path) as img:
                # Save each image directly as ICO format
                ico_path = f"temp_{i}.ico"
                img.save(ico_path, format="ICO")
                ico_files.append(ico_path)

        # Convert ICO files to DLL
        dll_filename = "IconLib.dll"
        dll_bytes = ico_to_dll(ico_files)

        # Save the DLL file
        with open(dll_filename, 'wb') as dll_file:
            dll_file.write(dll_bytes)

if __name__ == "__main__":
    main()