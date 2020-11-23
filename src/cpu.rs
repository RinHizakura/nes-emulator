use crate::opcodes;
use std::collections::HashMap;

pub struct CPU {
    pub reg_a: u8,
    pub reg_x: u8,
    pub reg_y: u8,
    pub status: u8,
    pub pc: u16,
    mem: [u8; 0xFFFF],
}

trait Mem {
    fn mem_read(&self, addr: u16) -> u8;
    fn mem_write(&mut self, addr: u16, data: u8);

    fn mem_read_u16(&self, pos: u16) -> u16 {
        let lo = self.mem_read(pos) as u16;
        let hi = self.mem_read(pos + 1) as u16;
        (hi << 8) | (lo)
    }

    fn mem_write_u16(&mut self, pos: u16, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.mem_write(pos, lo);
        self.mem_write(pos + 1, hi);
    }
}

impl Mem for CPU {
    fn mem_read(&self, addr: u16) -> u8 {
        self.mem[addr as usize]
    }

    fn mem_write(&mut self, addr: u16, data: u8) {
        self.mem[addr as usize] = data;
    }
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            reg_a: 0,
            reg_x: 0,
            reg_y: 0,
            status: 0,
            pc: 0,
            mem: [0; 0xFFFF],
        }
    }

    fn update_zn(&mut self, result: u8) {
        /* set zero flag */
        if result == 0 {
            self.status |= 0b00000010;
        } else {
            self.status &= 0b11111101;
        }

        /* set negative flag */
        if result & 0b1000_0000 != 0 {
            self.status |= 0b10000000;
        } else {
            self.status &= 0b01111111;
        }
    }

    fn get_operand_address(&self, mode: &opcodes::AddressingMode) -> u16 {
        match mode {
            opcodes::AddressingMode::Immediate => self.pc + 1,

            opcodes::AddressingMode::ZeroPage => self.mem_read(self.pc + 1) as u16,

            opcodes::AddressingMode::ZeroPageX => {
                let pos = self.mem_read(self.pc + 1);
                let addr = pos.wrapping_add(self.reg_x) as u16;
                addr
            }

            opcodes::AddressingMode::ZeroPageY => {
                let pos = self.mem_read(self.pc + 1);
                let addr = pos.wrapping_add(self.reg_y) as u16;
                addr
            }

            opcodes::AddressingMode::Absolute => self.mem_read_u16(self.pc + 1),

            opcodes::AddressingMode::AbsoluteX => {
                let pos = self.mem_read_u16(self.pc + 1);
                let addr = pos.wrapping_add(self.reg_x as u16);
                addr
            }

            opcodes::AddressingMode::AbsoluteY => {
                let pos = self.mem_read_u16(self.pc + 1);
                let addr = pos.wrapping_add(self.reg_y as u16);
                addr
            }

            opcodes::AddressingMode::Indirect => todo!(),

            opcodes::AddressingMode::IndirectX => {
                let base = self.mem_read(self.pc + 1);

                let ptr: u8 = (base as u8).wrapping_add(self.reg_x);
                let lo = self.mem_read(ptr as u16) as u16;
                let hi = self.mem_read(ptr.wrapping_add(1) as u16) as u16;
                (hi << 8) | (lo)
            }

            opcodes::AddressingMode::IndirectY => {
                let ptr = self.mem_read(self.pc + 1) as u8;
                let lo = self.mem_read(ptr as u16) as u16;
                let hi = self.mem_read(ptr.wrapping_add(1) as u16) as u16;
                let addr = (hi << 8) | (lo);

                addr.wrapping_add(self.reg_y as u16)
            }

            opcodes::AddressingMode::Relative => todo!(),

            /* for Implied mode, it should not call this function */
            opcodes::AddressingMode::Implied => {
                panic!("mode {:?} is not supported", mode);
            }
        }
    }

    fn lda(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.reg_a = value;
        self.update_zn(self.reg_a);
    }

    fn sta(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.reg_a);
    }

    fn tax(&mut self) {
        self.reg_x = self.reg_a;
        self.update_zn(self.reg_x);
    }

    fn inx(&mut self) {
        self.reg_x = self.reg_x.wrapping_add(1);
        self.update_zn(self.reg_x);
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.mem[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xFFFC, 0x8000);
    }

    pub fn reset(&mut self) {
        self.reg_a = 0;
        self.reg_x = 0;
        self.reg_y = 0;
        self.status = 0;

        self.pc = self.mem_read_u16(0xFFFC);
    }

    pub fn load_and_run(&mut self, program: Vec<u8>) {
        self.load(program);
        self.reset();
        self.run()
    }

    pub fn run(&mut self) {
        let ref opcodes_map: HashMap<u8, &'static opcodes::OpCode> = *opcodes::OPCODES_MAP;

        loop {
            let code = self.mem_read(self.pc);

            let opcode = opcodes_map
                .get(&code)
                .expect(&format!("OpCode {:x} is not recognized", code));

            match code {
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }

                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }

                0xAA => self.tax(),

                0xe8 => self.inx(),

                0x00 => return,
                _ => todo!(),
            }

            /* update PC according to the bytes needed for each instr */
            self.pc += (opcode.len) as u16;
        }
    }
}
