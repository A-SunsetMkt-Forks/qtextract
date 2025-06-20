/*
    Tool for extracting Qt resources from a x86/x64 Windows binary executables (.exe/.dll)
    by Austin
*/

pub mod binary_stream;
pub mod extractor;
pub mod aob;
pub mod image;

use std::{fs, env, io::Write, collections::HashSet};
use std::path::PathBuf;
use regex::{self, Regex};
use extractor::QtResourceInfo;
use binary_stream::BinaryReader;
use image::*;

const USAGE: &str = "usage: qtextract filename [options]
options:
  --help                   Print this help
  --chunk chunk_id         The chunk to dump. Exclude this to see a list of chunks (if any can be found) and use 0 to dump all chunks
  --output directory       For specifying an output directory
  --scanall                Scan the entire file (instead of the first executable section)
  --section section        For scanning a specific section
  --data, --datarva info   [Advanced] Use these options to manually provide offsets to a qt resource in the binary
                           (e.g. if no chunks were found automatically by qtextract).
                           'info' should use the following format: %x,%x,%x,%d
                           where the first 3 hexadecimal values are offsets to data, names, and tree
                           and the last decimal value is the version (usually 1-3).

                           If '--datarva' is used, provide RVA values (offsets from the image base) instead of file offsets.
                           See check_data_opt() in main.rs for an example on finding these offsets using IDA.";

fn check_opt_arg(flag: &str) -> Option<String> {
    env::args().skip_while(|s| s != flag).nth(1)
}

fn check_opt(flag: &str) -> bool {
    env::args().any(|s| s == flag)
}

// Q_CORE_EXPORT bool qRegisterResourceData(int version, const unsigned char *tree,
//                                          const unsigned char *name, const unsigned char *data)

struct SignatureDefinition {
    tag: &'static str,
    flags: usize,
    x64: bool,
    signature: &'static [(u8, bool)],
    extractor: fn(offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo>
}

impl SignatureDefinition {
    fn scan(&self, buffer: &[u8], index: usize, limit: usize) -> Option<usize> {
        debug_assert!(!self.signature.is_empty());
        assert!(limit >= index);
        if limit <= buffer.len() && limit - index >= self.signature.len() {
            let adjusted_limit = limit - self.signature.len();
            'outer: for i in index..=adjusted_limit {
                for j in 0..self.signature.len() {
                    let s = &self.signature[j];
                    if !s.1 && buffer[i+j] != s.0 {
                        continue 'outer;
                    }
                }
                return Some(i);
            }
        }
        None
    }

    fn scan_all(&self, buffer: &[u8], start: usize, end: usize) -> Vec<usize> {
        let mut results = Vec::<usize>::new();
        let mut i = start;
        loop {
            let Some(next) = self.scan(buffer, i, end) else {
                break;
            };
            results.push(next);
            i = next + 1;
        }
        results
    }
}

fn x86_extract(offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo> {
    let mut offsets = [0u64; 3];

    let mut stream = BinaryReader::new(bytes);
    for i in 0..3 {
        stream.skip(1); // skip 0x68 (push)
        offsets[i] = image.va2fo(stream.read_u32::<false>()?.into())?;
    }
    stream.skip(1); // skip 0x6A (push)
    let version = stream.read_byte()? as usize;

    Some(QtResourceInfo {
        signature_tag: None,
        registrar: offset as u64,
        data: offsets[0],
        name: offsets[1],
        tree: offsets[2],
        version
    })
}

fn x64_extract_dntv(bytes_offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo> {
    let mut result = [0u64; 3];
    let bytes_va = image.fo2va(bytes_offset as u64)?;
    let mut stream = BinaryReader::new_at(bytes, 0);

    for i in 0..3 {
        stream.skip(3);
        let v = stream.read_i32::<false>()?;
        result[i] = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    }

    stream.skip(1);
    let version = stream.read_u32::<false>()? as usize;

    Some(QtResourceInfo {
        signature_tag: None,
        registrar: bytes_offset as u64,
        data: result[0],
        name: result[1],
        tree: result[2],
        version
    })
}

fn x64_extract_tndv(bytes_offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo> {
    let mut result = [0u64; 3];
    let bytes_va = image.fo2va(bytes_offset as u64)?;
    let mut stream = BinaryReader::new_at(bytes, 0);

    for i in 0..3 {
        stream.skip(3);
        let v = stream.read_i32::<false>()?;
        result[i] = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    }

    stream.skip(1);
    let version = stream.read_u32::<false>()? as usize;

    Some(QtResourceInfo {
        signature_tag: None,
        registrar: bytes_offset as u64,
        data: result[2],
        name: result[1],
        tree: result[0],
        version
    })
}

fn x64_extract_dvnt(bytes_offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo> {
    let bytes_va = image.fo2va(bytes_offset as u64)?;
    let mut stream = BinaryReader::new_at(bytes, 0);
    let mut v: i32;

    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let data = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    stream.skip(1);
    let version = stream.read_u32::<false>()? as usize;
    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let name = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let tree = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    
    Some(QtResourceInfo {
        signature_tag: None,
        registrar: bytes_offset as u64,
        data,
        name,
        tree,
        version
    })
}

fn x86_extract_mingw(bytes_offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo> {
    let mut result = [0u64; 3];
    let mut stream = BinaryReader::new_at(bytes, 0);

    for i in 0..3 {
        stream.skip(4);
        let v = stream.read_u32::<false>()? as u64;
        result[i] = image.va2fo(v)?;
    }

    stream.skip(3);
    let version = stream.read_u32::<false>()? as usize;

    Some(QtResourceInfo {
        signature_tag: None,
        registrar: bytes_offset as u64,
        data: result[0],
        name: result[1],
        tree: result[2],
        version
    })
}

fn x64_extract_dnvt(bytes_offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo> {
    let bytes_va = image.fo2va(bytes_offset as u64)?;
    let mut stream = BinaryReader::new_at(bytes, 0);
    let mut v: i32;

    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let data = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;

    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let name = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;

    stream.skip(1);
    let version = stream.read_u32::<false>()? as usize;

    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let tree = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    
    Some(QtResourceInfo {
        signature_tag: None,
        registrar: bytes_offset as u64,
        data,
        name,
        tree,
        version
    })
}

fn x64_extract_ntvd(bytes_offset: usize, bytes: &[u8], image: &Image) -> Option<QtResourceInfo> {
    let bytes_va = image.fo2va(bytes_offset as u64)?;
    let mut stream = BinaryReader::new_at(bytes, 0);
    let mut v: i32;

    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let name = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;

    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let tree = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    
    stream.skip(1);
    let version = stream.read_u32::<false>()? as usize;

    stream.skip(3);
    v = stream.read_i32::<false>()?;
    let data = image.va2fo((bytes_va + stream.position() as u64).wrapping_add_signed(v.into()))?;
    
    Some(QtResourceInfo {
        signature_tag: None,
        registrar: bytes_offset as u64,
        data,
        name,
        tree,
        version
    })
}

static TEXT_SIGNATURES: &[SignatureDefinition] = &[
    SignatureDefinition {
        /*
        msvc, 32-bit, absolute offsets
        sample: RPGMV, old RobloxStudioBeta

        68 00 00 00 00          push   0x0
        68 00 00 00 00          push   0x0
        68 00 00 00 00          push   0x0
        6a 00                   push   0x0
        e8 00 00 00 00          call   0x16
         */

        tag: "msvc-x86_0",
        flags: IMAGE_FLAGS_PE,
        x64: false,
        signature: define_signature!(b"68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ??"),
        extractor: x86_extract
    },
    SignatureDefinition {
        /*
        msvc, 32-bit, absolute offsets
        sample: RPGMZ

        68 00 00 00 00          push   0x0
        68 00 00 00 00          push   0x0
        68 00 00 00 00          push   0x0
        6a 00                   push   0x0
        ff 15 00 00 00 00       call   DWORD PTR ds:0x0
         */
        tag: "msvc-x86_1",
        flags: IMAGE_FLAGS_PE,
        x64: false,
        signature: define_signature!(b"68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? FF 15"),
        extractor: x86_extract
    },
    SignatureDefinition {
        /*
        msvc, 64-bit, relative offsets
        sample: RobloxStudioBeta

        4c 8d 0d 00 00 00 00    lea    r9,[rip+0x0]
        4c 8d 05 00 00 00 00    lea    r8,[rip+0x0]
        48 8d 15 00 00 00 00    lea    rdx,[rip+0x0]
        b9 00 00 00 00          mov    ecx,0x0
        e8 00 00 00 00          call   0x0
         */
        tag: "msvc-x64_0",
        flags: IMAGE_FLAGS_PE,
        x64: true,
        signature: define_signature!(b"4C 8D 0D ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 ?? 00 00 00 E8"),
        extractor: x64_extract_dntv
    },
    SignatureDefinition {
        /*
        msvc, 64-bit, relative offsets
        sample: Chatterino

        4c 8d 0d 00 00 00 00    lea    r9,[rip+0x0]
        4c 8d 05 00 00 00 00    lea    r8,[rip+0x0]
        48 8d 15 00 00 00 00    lea    rdx,[rip+0x0]
        b9 00 00 00 00          mov    ecx,0x0
        ff 15 ef d7 02 00       call   QWORD PTR [rip+0x0]
         */
        tag: "msvc-x64_1",
        flags: IMAGE_FLAGS_PE,
        x64: true,
        signature: define_signature!(b"4C 8D 0D ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 ?? 00 00 00 FF 15"),
        extractor: x64_extract_dntv
    },
    SignatureDefinition {
        /*
        msvc, 64-bit, relative offsets
        sample: Wireshark, RobloxStudioBeta

        4c 8d 0d 00 00 00 00    lea    r9,[rip+0x0]
        b9 00 00 00 00          mov    ecx,0x0
        4c 8d 05 00 00 00 00    lea    r8,[rip+0x0]
        48 8d 15 00 00 00 00    lea    rdx,[rip+0x0]
        e8 00 00 00 00          call   0x23
         */
        tag: "msvc-x64_2",
        flags: IMAGE_FLAGS_PE,
        x64: true,
        signature: define_signature!(b"4C 8D 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? E8"),
        extractor: x64_extract_dvnt
    },
    SignatureDefinition {
        /*
        msvc, 64-bit, relative offsets
        sample: Chatterino

        4c 8d 0d 00 00 00 00    lea    r9,[rip+0x0]
        b9 00 00 00 00          mov    ecx,0x0
        4c 8d 05 00 00 00 00    lea    r8,[rip+0x0]
        48 8d 15 00 00 00 00    lea    rdx,[rip+0x0]
        ff 15 00 00 00 00       call   QWORD PTR [rip+0x0]
         */
        tag: "msvc-x64_3",
        flags: IMAGE_FLAGS_PE,
        x64: true,
        signature: define_signature!(b"4C 8D 0D ?? ?? ?? ?? B9 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? FF 15"),
        extractor: x64_extract_dvnt
    },
    SignatureDefinition {
        /*
        mingw, 32-bit, absolute offsets (see issue #8)
        sample: Radar-PCManager (see issue #8)

        c7 44 24 0c 00 00 00 00 mov    DWORD PTR [esp+0xc],0x0
        c7 44 24 08 00 00 00 00 mov    DWORD PTR [esp+0x8],0x0
        c7 44 24 04 00 00 00 00 mov    DWORD PTR [esp+0x4],0x0
        c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
        ff 15 00 00 00 00       call   DWORD PTR ds:0x0
         */
        tag: "mingw-x86_0",
        flags: IMAGE_FLAGS_PE,
        x64: false,
        signature: define_signature!(b"C7 44 24 0C ?? ?? ?? ?? C7 44 24 08 ?? ?? ?? ?? C7 44 24 04 ?? ?? ?? ?? C7 04 24 ?? 00 00 00 FF 15"),
        extractor: x86_extract_mingw
    },
    SignatureDefinition {
        /*
        mingw, 32-bit, absolute offsets

        c7 44 24 0c 00 00 00 00 mov    DWORD PTR [esp+0xc],0x0
        c7 44 24 08 00 00 00 00 mov    DWORD PTR [esp+0x8],0x0
        c7 44 24 04 00 00 00 00 mov    DWORD PTR [esp+0x4],0x0
        c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
        e8 00 00 00 00          call   0x0
         */
        tag: "mingw-x86_1",
        flags: IMAGE_FLAGS_PE,
        x64: false,
        signature: define_signature!(b"C7 44 24 0C ?? ?? ?? ?? C7 44 24 08 ?? ?? ?? ?? C7 44 24 04 ?? ?? ?? ?? C7 04 24 ?? 00 00 00 E8"),
        extractor: x86_extract_mingw
    },
    SignatureDefinition {
        /*
        gcc/clang, 64-bit, relative offsets
        sample: Chatterino (Linux)

        48 8d 0d 00 00 00 00    lea    rcx,[rip+0x0] # data
        48 8d 15 00 00 00 00    lea    rdx,[rip+0x0] # name
        bf 03 00 00 00          mov    edi,0x3 # version
        48 8d 35 00 00 00 00    lea    rsi,[rip+0x0] # tree
        e8 00 00 00 00          call   0x0
         */

        tag: "gnu-x64-dnvt",
        flags: IMAGE_FLAGS_ELF | IMAGE_FLAGS_MACHO,
        x64: true,
        signature: define_signature!(b"48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? BF ?? 00 00 00 48 8D 35 ?? ?? ?? ?? E8"),
        extractor: x64_extract_dnvt
    },
    SignatureDefinition {
        /*
        gcc/clang, 64-bit, relative offsets
        sample: Chatterino (Linux)

        48 8d 15 00 00 00 00    lea    rdx,[rip+0x0] # name
        48 8d 35 00 00 00 00    lea    rsi,[rip+0x0] # tree
        bf 03 00 00 00          mov    edi,0x3 # version
        48 8d 0d 00 00 00 00    lea    rcx,[rip+0x0] # data
        e8 00 00 00 00          call   0x0
         */

        tag: "gnu-x64-ntvd",
        flags: IMAGE_FLAGS_ELF | IMAGE_FLAGS_MACHO,
        x64: true,
        signature: define_signature!(b"48 8D 15 ?? ?? ?? ?? 48 8D 35 ?? ?? ?? ?? BF ?? 00 00 00 48 8D 0D ?? ?? ?? ?? E8"),
        extractor: x64_extract_ntvd
    },
    SignatureDefinition {
        /*
        gcc/clang, 64-bit, relative offsets
        sample: Chatterino (Mac)

        48 8d 35 00 00 00 00    lea    rsi,[rip+0x0] # tree
        48 8d 15 00 00 00 00    lea    rdx,[rip+0x0] # name
        48 8d 0d 00 00 00 00    lea    rcx,[rip+0x0] # data
        bf 03 00 00 00          mov    edi,0x3 # version
        e8 00 00 00 00          call   0x0
         */

        tag: "gnu-x64-tndv",
        flags: IMAGE_FLAGS_ELF | IMAGE_FLAGS_MACHO,
        x64: true,
        signature: define_signature!(b"48 8D 35 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? BF ?? 00 00 00 E8"),
        extractor: x64_extract_tndv
    }
];

fn get_target_section<'a>(image: &'a Image) -> Option<&'a ImageSection> {
    if !check_opt("--scanall") {
        if let Some(target) = check_opt_arg("--section") {
            for v in &image.sections {
                if let Some(name) = &v.name {
                    if *name == target {
                        return Some(v);
                    }
                }
            }
        } else {
            return image.sections.iter().find(|x| x.is_code);
        }
    }
    None
}

fn do_scan(buffer: &[u8], start: usize, end: usize, image: &Image) -> Vec<QtResourceInfo> {
    let mut seen = HashSet::<u64>::new();
    let mut results = Vec::<QtResourceInfo>::new();

    let signatures: Vec<&SignatureDefinition> = TEXT_SIGNATURES.iter().filter(|x| x.x64 == image.is_x64() && image.flags & x.flags != 0).collect();

    println!("Applicable signatures: {}", signatures.len());

    for def in signatures {
        for fo in def.scan_all(buffer, start, end) {
            if let Some(mut info) = (def.extractor)(fo, &buffer[fo..fo+def.signature.len()], image) {
                if info.version < 10 { // simple sanity check
                    if seen.insert(info.data) {
                        info.signature_tag = Some(def.tag);
                        results.push(info);
                    }
                    continue;
                }
            }

            #[cfg(debug_assertions)]
            println!("DEBUG: Failed to extract parameters from signature at {:#08X}. Likely false positive", fo);
        }
    }

    results
}

fn check_data_opt(image: &Image) -> Option<Vec<QtResourceInfo>> {
    // For providing resource chunk information that couldn't be found automatically
	// If using IDA: The offsets can be found by setting the image base in IDA to 0 ( Edit->Segments->Rebase program... https://i.imgur.com/XWIzhEf.png ) 
	// and then looking at calls to qRegisterResourceData ( https://i.imgur.com/D0gjkbH.png ) to extract the offsets.
	// The chunk can then be dumped with this program using --datarva data,name,tree,version

    let mut data_arg_opt = check_opt_arg("--data");
    let mut is_rva = false;

    if data_arg_opt.is_none() {
        data_arg_opt = check_opt_arg("--datarva");
        is_rva = true;
    }

    if let Some(data_arg) = data_arg_opt {
        let regex = Regex::new(r"([a-fA-F0-9]+),([a-fA-F0-9]+),([a-fA-F0-9]+),([0-9]+)").unwrap();
        if let Some(captures) = regex.captures(data_arg.as_str()) {
            let mut offsets = [0u64; 3];

            if is_rva {
                for i in 1..=3 {
                    offsets[i - 1] = image.rva2fo(u64::from_str_radix(&captures[i], 16).unwrap()).expect("invalid rva passed to `datarva`");
                }
            } else {
                for i in 1..=3 {
                    offsets[i - 1] = u64::from_str_radix(&captures[i], 16).unwrap();
                }
            }

            let version = captures[4].parse().unwrap();

            return Some(vec![ QtResourceInfo { signature_tag: None, registrar: 0, data: offsets[0], name: offsets[1], tree: offsets[2], version } ]);
        }
    }

    None
}

// returns a pointer to a function like this: https://i.imgur.com/ilfgGPG.png
fn ask_resource_data(buffer: &[u8], image: &Image) -> Option<Vec<QtResourceInfo>> {
    let start: usize;
    let end: usize;

    if let Some(section) = get_target_section(image) {
        start = section.file_offset as usize;
        end = start + section.size as usize;
        println!("Scanning section {} ({:#08x}-{:#08x})...", section.name.as_deref().unwrap_or("N/A"), start, end);
    } else {
        start = 0;
        end = buffer.len();
        println!("Scanning file...");
    }

    let start_time = std::time::Instant::now();
    let results = do_scan(buffer, start, end, image);
    println!("Done in {:.2?}", start_time.elapsed());

    if !results.is_empty() {
        let chunk_id = if let Some(arg) = check_opt_arg("--chunk") {
            let id: usize = arg.trim().parse().expect("integer value expected for `chunk` parameter");
            assert!(id <= results.len(), "value provided by `chunk` parameter is out of range");
            id
        } else {
            println!("Select a resource chunk to dump:");
            println!("0 - Dump all");
            
            for (i, result) in results.iter().enumerate() {
                println!("{} - {:#08X} (via signature {}: version={}, data={:#08X}, name={:#08X}, tree={:#08X})", i + 1, result.registrar, result.signature_tag.unwrap_or("n/a"), result.version, result.data, result.name, result.tree);
            }

            println!();

            loop {
                print!(">");
                std::io::stdout().flush().unwrap();

                let mut input = String::new();
                let _ = std::io::stdin().read_line(&mut input);
                let selection = input.trim().parse::<usize>().unwrap_or(usize::MAX);

                if selection <= results.len() {
                    break selection;
                }

                println!("Please enter a number between 0 and {}", results.len());
            }
        };

        return Some(if chunk_id == 0 {
            results
        } else {
            vec![ results[chunk_id - 1] ]
        });
    }

    None
}

fn main() {
    let Some(path) = env::args().nth(1) else {
        println!("{USAGE}");
        return
    };

    if check_opt("--help") {
        println!("{USAGE}");
        return
    }

    let buffer = fs::read(&path).expect("failed to read input file");
    let image = Image::from(&buffer).expect("invalid executable file");    
    let output_directory = PathBuf::from(check_opt_arg("--output").unwrap_or("qtextract-output".to_string()));

    if let Some(to_dump) = check_data_opt(&image).or_else(|| ask_resource_data(&buffer, &image)) {
        for (i, result) in to_dump.iter().enumerate() {
            print!("Extracting chunk #{} ({:#08X})... ", i + 1, result.registrar);

            let dump_path = if to_dump.len() > 1 {
                output_directory.join((i + 1).to_string())
            } else {
                output_directory.clone()
            };

            if let Some(node) = result.parse_node(&buffer, 0) {
                println!("OK");
                println!("---");
                node.dump(&dump_path).expect("failed to dump node");
            } else {
                println!("ERROR (failed to parse node)");
            }
        }
    } else {
        println!("No chunks to dump");
    }
}
