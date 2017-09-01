extern crate r2pipe;
#[macro_use]
extern crate serde_json;

use r2pipe::R2Pipe;
use serde_json::value::Value as json;
use std::process;
use std::collections::VecDeque;

fn find_text_section(json: &json) -> json {
    let mut section = json!(null);
    for value in json.as_array().unwrap() {
        if value["name"] == ".text" {
           section = json!(value);
        }
    }
    section
}

fn print_gadget(gadget: &mut VecDeque<String>) {
    println!("\n");
    while gadget.len() > 0 {
        match gadget.pop_back() {
            Some(x) => println!("{}", x),
            None => (),
        }
    }
}

fn trim_string(s: String) -> String {
    let mut bytes = s;
    if bytes.len() > 5 {
        let end: &str = ".\"";
        bytes.truncate(5);
        bytes.push_str(end);
    }
    bytes
}

fn find_rop_gadgets(json: json) {
    let disassm = json.as_array().unwrap();
    for (key, value) in disassm.iter().enumerate() {
        //ret instruction, adjust as needed
        if value["opcode"].to_string().contains("ret") {
            let mut gadget = VecDeque::new();
            for i in 0..9 {
                let addr = if (key - i) > 0 { key - i } else { 0 };
                let d_line = &disassm[addr];
                if i != 0 
                    && (d_line["opcode"].to_string().contains("ret") 
                    || d_line["opcode"].to_string().contains("call")) {
                    break;
                } 
                let offset = d_line["offset"].to_string().parse::<i32>().unwrap();
                let bytes = trim_string(d_line["bytes"].to_string()); 
                let opcode = format!("{:#x}\t{1}\t{2}", offset, bytes, d_line["opcode"]);
                gadget.push_back(opcode);
            }
            print_gadget(&mut gadget);
        }
    }
}

fn main() {
    let bin = "/bin/ls";
    let mut r2p = R2Pipe::spawn(bin, None).unwrap();
    let json = r2p.cmdj("iSj").unwrap();
    let section = find_text_section(&json);
    if section.is_null() {
        println!("[-] No text section found. Exiting...");
        process::exit(1);
    }
    println!("{}", section);
    let disass_cmd = format!("pDj {0} @{1}", section["size"], section["vaddr"]);
    let json = r2p.cmdj(&disass_cmd).unwrap();
    find_rop_gadgets(json);
    match r2p.cmd("q") {
        Err(err) => panic!("Error: {}", err),
        _ => (), 
    }
    r2p.close();
    println!("[+] Done");
}
