use crate::opcodes;
use std::collections::HashMap;

macro_rules! is_accum {
    ($mode:ident) => {
        match $mode {
            opcodes::AddressingMode::NoneAddressing => true,
            _ => false,
        };
    };
}

bitflags! {
    pub struct CpuFlags: u8 {
        const CARRY             = 0b00000001;
        const ZERO              = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE      = 0b00001000;
        const BREAK1            = 0b00010000;
        const BREAK2            = 0b00100000;
        const BREAK             = 0b00110000;
        const OVERFLOW          = 0b01000000;
        const NEGATIVE          = 0b10000000;
    }
}

const STACK_BASE: u16 = 0x0100;

pub struct CPU {
    pub reg_a: u8,
    pub reg_x: u8,
    pub reg_y: u8,
    pub status: CpuFlags,
    pub pc: u16,
    pub sp: u8,
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
            status: CpuFlags::from_bits_truncate(0b100100),
            pc: 0,
            sp: 0xfd,
            mem: [0; 0xFFFF],
        }
    }

    #[inline]
    fn set_flag(&mut self, cond: bool, flag: CpuFlags) {
        if cond {
            self.status.insert(flag);
        } else {
            self.status.remove(flag);
        }
    }

    /* FIXME: how about a general `set_reg` for every register? */
    fn set_reg_a(&mut self, value: u8) {
        self.reg_a = value;
        self.update_zn(self.reg_a);
    }

    fn set_reg_x(&mut self, value: u8) {
        self.reg_x = value;
        self.update_zn(self.reg_x);
    }

    fn set_reg_y(&mut self, value: u8) {
        self.reg_y = value;
        self.update_zn(self.reg_y);
    }

    fn set_mem(&mut self, addr: u16, value: u8) {
        self.mem_write(addr, value);
        self.update_zn(self.mem[addr as usize]);
    }

    fn add_reg_a(&mut self, data: u8) {
        let sum = self.reg_a as u16
            + data as u16
            + (if self.status.contains(CpuFlags::CARRY) {
                1
            } else {
                0
            }) as u16;

        self.set_flag(sum > 0xff, CpuFlags::CARRY);

        let result = sum as u8;

        self.set_flag(
            ((data ^ result) & (self.reg_a ^ result) & 0x80) != 0,
            CpuFlags::OVERFLOW,
        );
        self.set_reg_a(result);
    }

    fn update_zn(&mut self, result: u8) {
        /* set zero flag */
        self.set_flag(result == 0, CpuFlags::ZERO);

        /* set negative flag */
        self.set_flag(result & 0b1000_0000 != 0, CpuFlags::NEGATIVE);
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

            /* since the only Indirect mode instruction is JMP, and this mode of JMP
            has bug in 6502, we implement the bug here accordingly */
            opcodes::AddressingMode::Indirect => {
                let pos = self.mem_read_u16(self.pc + 1);
                let addr = if pos & 0x00FF == 0x00FF {
                    let lo = self.mem_read(pos) as u16;
                    let hi = self.mem_read(pos & 0xFF00) as u16;
                    hi << 8 | lo
                } else {
                    self.mem_read_u16(pos)
                };
                addr
            }

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
            opcodes::AddressingMode::NoneAddressing => {
                panic!("mode {:?} is not supported", mode);
            }
        }
    }

    fn stack_push(&mut self, data: u8) {
        self.mem_write(STACK_BASE + self.sp as u16, data);
        self.sp = self.sp.wrapping_sub(1)
    }

    fn stack_push_u16(&mut self, data: u16) {
        let hi = (data >> 8) as u8;
        let lo = (data & 0xff) as u8;
        self.stack_push(hi);
        self.stack_push(lo);
    }

    fn stack_pop(&mut self) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        self.mem_read(STACK_BASE + self.sp as u16)
    }

    fn stack_pop_u16(&mut self) -> u16 {
        let lo = self.stack_pop() as u16;
        let hi = self.stack_pop() as u16;
        hi << 8 | lo
    }

    /* Arithmetic */
    fn adc(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.add_reg_a(value);
    }

    fn sbc(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        /* subtract number `n` should equal to add `-n` */
        self.add_reg_a(((value as i8).wrapping_neg().wrapping_sub(1)) as u8);
    }

    fn and(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        self.set_reg_a(value ^ self.reg_a);
    }

    fn eor(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        self.set_reg_a(value ^ self.reg_a);
    }

    fn ora(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        self.set_reg_a(value | self.reg_a);
    }

    /* Shifts */
    fn asl(&mut self, mode: &opcodes::AddressingMode) {
        let cond = is_accum!(mode);

        if cond {
            let mut value = self.reg_a;
            value <<= 1;
            self.set_reg_a(value);
        } else {
            let addr = self.get_operand_address(mode);
            let mut value = self.mem_read(addr);
            value <<= 1;
            self.set_mem(addr, value);
        }
    }

    fn lsr(&mut self, mode: &opcodes::AddressingMode) {
        let cond = is_accum!(mode);

        if cond {
            let mut value = self.reg_a;

            /* Set to contents of old bit 0 */
            self.set_flag(value & 1 == 1, CpuFlags::CARRY);
            value >>= 1;

            self.set_reg_a(value);
        } else {
            let addr = self.get_operand_address(mode);
            let mut value = self.mem_read(addr);

            /* Set to contents of old bit 0 */
            self.set_flag(value & 1 == 1, CpuFlags::CARRY);

            value >>= 1;
            self.set_mem(addr, value);
        }
    }

    fn rol(&mut self, mode: &opcodes::AddressingMode) {
        let cond = is_accum!(mode);

        if cond {
            let mut value = self.reg_a;

            let old_carry = self.status.contains(CpuFlags::CARRY);
            self.set_flag(value >> 7 == 1, CpuFlags::CARRY);
            value = (value << 1) | (old_carry as u8);

            self.set_reg_a(value);
        } else {
            let addr = self.get_operand_address(mode);
            let mut value = self.mem_read(addr);

            let old_carry = self.status.contains(CpuFlags::CARRY);
            self.set_flag(value >> 7 == 1, CpuFlags::CARRY);
            value = (value << 1) | (old_carry as u8);

            self.set_mem(addr, value);
        }
    }

    fn ror(&mut self, mode: &opcodes::AddressingMode) {
        let cond = is_accum!(mode);

        if cond {
            let mut value = self.reg_a;
            let old_carry = self.status.contains(CpuFlags::CARRY);

            self.set_flag(value & 1 == 1, CpuFlags::CARRY);
            value = (value >> 1) | (old_carry as u8) << 7;

            self.set_reg_a(value);
        } else {
            let addr = self.get_operand_address(mode);
            let mut value = self.mem_read(addr);

            let old_carry = self.status.contains(CpuFlags::CARRY);
            self.set_flag(value & 1 == 1, CpuFlags::CARRY);
            value = (value >> 1) | (old_carry as u8) << 7;

            self.set_mem(addr, value);
        }
    }
    /* Stores, Loads */
    fn lda(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let value = self.mem_read(addr);

        self.set_reg_a(value);
    }

    fn sta(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.reg_a);
    }

    fn ldx(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        self.set_reg_x(value);
    }

    fn ldy(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        self.set_reg_y(value);
    }

    fn stx(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.reg_x);
    }

    fn sty(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.mem_write(addr, self.reg_y);
    }

    /* Inc, Dec */
    fn inc(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(&mode);
        let mut value = self.mem_read(addr);
        value = value.wrapping_add(1);
        self.set_mem(addr, value);
    }

    fn dec(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        let mut value = self.mem_read(addr);
        value = value.wrapping_sub(1);
        self.set_mem(addr, value);
    }

    fn inx(&mut self) {
        self.set_reg_x(self.reg_x.wrapping_add(1));
    }

    fn iny(&mut self) {
        self.set_reg_y(self.reg_y.wrapping_add(1));
    }

    fn dex(&mut self) {
        self.set_reg_x(self.reg_x.wrapping_sub(1));
    }

    fn dey(&mut self) {
        self.set_reg_y(self.reg_y.wrapping_sub(1));
    }

    /* Compare */
    fn cmp(&mut self, mode: &opcodes::AddressingMode, target: u8) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        self.set_flag(value <= target, CpuFlags::CARRY);
        self.update_zn(target.wrapping_sub(value));
    }

    fn bit(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        let value = self.mem_read(addr);
        self.set_flag((self.reg_a & value) == 0, CpuFlags::ZERO);

        self.status.set(CpuFlags::NEGATIVE, value & 0b10000000 > 0);
        self.status.set(CpuFlags::OVERFLOW, value & 0b01000000 > 0);
    }

    /* Branching */
    fn jmp(&mut self, mode: &opcodes::AddressingMode) {
        let addr = self.get_operand_address(mode);
        self.pc = addr
    }

    fn branch(&mut self, condition: bool) {
        if condition {
            let d: u16 = self.mem_read(self.pc + 1) as u16;
            /* relative bytes counted from next pc value */
            let jump_addr = self.pc.wrapping_add(2).wrapping_add(d as u16);

            self.pc = jump_addr;
        }
    }

    /* others */
    fn tax(&mut self) {
        self.set_reg_x(self.reg_a);
    }

    pub fn load(&mut self, program: Vec<u8>) {
        self.mem[0x8000..(0x8000 + program.len())].copy_from_slice(&program[..]);
        self.mem_write_u16(0xFFFC, 0x8000);
    }

    pub fn reset(&mut self) {
        self.reg_a = 0;
        self.reg_x = 0;
        self.reg_y = 0;

        self.status = CpuFlags::from_bits_truncate(0b100100); // 0x34
        self.pc = self.mem_read_u16(0xFFFC);
        self.sp = 0xfd;

        println!("status {}", self.status.bits());
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

            let pc_state = self.pc;

            match code {
                /* Arithmetic */
                0x69 | 0x65 | 0x75 | 0x6d | 0x7d | 0x79 | 0x61 | 0x71 => {
                    self.adc(&opcode.mode);
                }
                0xe9 | 0xe5 | 0xf5 | 0xed | 0xfd | 0xf9 | 0xe1 | 0xf1 => {
                    self.sbc(&opcode.mode);
                }
                0x29 | 0x25 | 0x35 | 0x2d | 0x3d | 0x39 | 0x21 | 0x31 => {
                    self.and(&opcode.mode);
                }
                0x49 | 0x45 | 0x55 | 0x4d | 0x5d | 0x59 | 0x41 | 0x51 => {
                    self.eor(&opcode.mode);
                }
                0x09 | 0x05 | 0x15 | 0x0d | 0x1d | 0x19 | 0x01 | 0x11 => {
                    self.ora(&opcode.mode);
                }

                /* Shifts */
                0x0a | 0x06 | 0x16 | 0x0e | 0x1e => {
                    self.asl(&opcode.mode);
                }
                0x4a | 0x46 | 0x56 | 0x4e | 0x5e => {
                    self.lsr(&opcode.mode);
                }
                0x2a | 0x26 | 0x36 | 0x2e | 0x3e => {
                    self.rol(&opcode.mode);
                }
                0x6a | 0x66 | 0x76 | 0x6e | 0x7e => {
                    self.ror(&opcode.mode);
                }

                /* Stores, Loads */
                0xa9 | 0xa5 | 0xb5 | 0xad | 0xbd | 0xb9 | 0xa1 | 0xb1 => {
                    self.lda(&opcode.mode);
                }
                0x85 | 0x95 | 0x8d | 0x9d | 0x99 | 0x81 | 0x91 => {
                    self.sta(&opcode.mode);
                }
                0xa2 | 0xa6 | 0xb6 | 0xae | 0xbe => {
                    self.ldx(&opcode.mode);
                }
                0xa0 | 0xa4 | 0xb4 | 0xac | 0xbc => {
                    self.ldy(&opcode.mode);
                }
                0x86 | 0x96 | 0x8e => {
                    self.stx(&opcode.mode);
                }
                0x84 | 0x94 | 0x8c => {
                    self.sty(&opcode.mode);
                }

                /* Inc, Dec */
                0xe6 | 0xf6 | 0xee | 0xfe => {
                    self.inc(&opcode.mode);
                }
                0xc6 | 0xd6 | 0xce | 0xde => {
                    self.dec(&opcode.mode);
                }
                0xe8 => self.inx(),
                0xc8 => self.iny(),
                0xca => self.dex(),
                0x88 => self.dey(),

                /* Compare */
                0xc9 | 0xc5 | 0xd5 | 0xcd | 0xdd | 0xd9 | 0xc1 | 0xd1 => {
                    self.cmp(&opcode.mode, self.reg_a);
                }
                0xc0 | 0xc4 | 0xcc => {
                    self.cmp(&opcode.mode, self.reg_y);
                }
                0xe0 | 0xe4 | 0xec => {
                    self.cmp(&opcode.mode, self.reg_x);
                }
                0x24 | 0x2c => {
                    self.bit(&opcode.mode);
                }
                /* Branching */
                0x4c | 0x6c => {
                    self.jmp(&opcode.mode);
                }
                0x20 => {
                    self.stack_push_u16(self.pc + 2);
                    self.jmp(&opcode.mode);
                }
                0x60 => {
                    self.pc = self.stack_pop_u16() + 1;
                }
                0x40 => {
                    /* FIXME: is it correct to ignore break status bit? */
                    self.status.bits = self.stack_pop() & CpuFlags::BREAK.bits;
                    self.pc = self.stack_pop_u16();
                }
                0xd0 => {
                    self.branch(!self.status.contains(CpuFlags::ZERO));
                }
                0x70 => {
                    self.branch(self.status.contains(CpuFlags::OVERFLOW));
                }
                0x50 => {
                    self.branch(!self.status.contains(CpuFlags::OVERFLOW));
                }
                0x30 => {
                    self.branch(self.status.contains(CpuFlags::NEGATIVE));
                }
                0xf0 => {
                    self.branch(self.status.contains(CpuFlags::ZERO));
                }
                0xb0 => {
                    self.branch(self.status.contains(CpuFlags::CARRY));
                }
                0x90 => {
                    self.branch(!self.status.contains(CpuFlags::CARRY));
                }
                0x10 => {
                    self.branch(!self.status.contains(CpuFlags::NEGATIVE));
                }
                /* flag clear */
                0xd8 => self.status.remove(CpuFlags::DECIMAL_MODE),
                0x58 => self.status.remove(CpuFlags::INTERRUPT_DISABLE),
                0xb8 => self.status.remove(CpuFlags::OVERFLOW),
                0x18 => self.status.remove(CpuFlags::CARRY),
                0x38 => self.status.insert(CpuFlags::CARRY),
                0x78 => self.status.insert(CpuFlags::INTERRUPT_DISABLE),
                0xf8 => self.status.insert(CpuFlags::DECIMAL_MODE),

                /* others */
                0xAA => self.tax(),
                0x00 => {
                    /* FIXME shouldn't we set the break flag here ? */
                    return;
                }
                _ => todo!(),
            }

            /* update PC according to the bytes needed for each instr
            if pc didn't be changed by an instruction */
            if self.pc == pc_state {
                self.pc += (opcode.len) as u16;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::CpuFlags;
    use super::CPU;

    #[test]
    fn test_lda_imm_tax_pos() {
        let mut cpu = CPU::new();

        for value in 0x01..0x80 {
            let mut v = Vec::new();
            v.push(0xa9);
            v.push(value);
            v.push(0xaa);
            v.push(0x00);

            cpu.load_and_run(v);

            /* value checking */
            assert_eq!(cpu.reg_a, value);
            /* status checking: Z should be 0 and N should be 0 */
            assert!(!cpu.status.contains(CpuFlags::ZERO | CpuFlags::NEGATIVE));

            assert_eq!(cpu.reg_x, cpu.reg_a);
            assert!(!cpu.status.contains(CpuFlags::ZERO | CpuFlags::NEGATIVE));
        }
    }

    #[test]
    fn test_lda_imm_tax_zero() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x00, 0xaa, 0x00]);
        assert!(cpu.status.contains(CpuFlags::ZERO));
        assert!(!cpu.status.contains(CpuFlags::NEGATIVE));

        assert_eq!(cpu.reg_x, cpu.reg_a);
        assert!(cpu.status.contains(CpuFlags::ZERO));
        assert!(!cpu.status.contains(CpuFlags::NEGATIVE));
    }

    #[test]
    fn test_lda_imm_tax_neg() {
        let mut cpu = CPU::new();

        for value in 0x080..=0xFF {
            let mut v = Vec::new();
            v.push(0xa9);
            v.push(value);
            v.push(0xaa);
            v.push(0x00);
            cpu.load_and_run(v);

            /* value checking */
            assert_eq!(cpu.reg_a, value);
            /* status checking: Z should be 0 and N should be 1 */
            assert!(!cpu.status.contains(CpuFlags::ZERO));
            assert!(cpu.status.contains(CpuFlags::NEGATIVE));

            assert_eq!(cpu.reg_x, cpu.reg_a);
            assert!(!cpu.status.contains(CpuFlags::ZERO));
            assert!(cpu.status.contains(CpuFlags::NEGATIVE));
        }
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xff, 0xaa, 0xe8, 0xe8, 0x00]);
        assert_eq!(cpu.reg_x, 1);
    }

    #[test]
    fn test_lda_sta_mem() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0x55, 0x85, 0x10, 0xa5, 0x10, 0x00]);

        assert_eq!(cpu.reg_a, 0x55);
    }

    #[test]
    fn test_target() {
        let mut cpu = CPU::new();
        cpu.load_and_run(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.reg_x, 0xc1)
    }

    #[test]
    fn test_asl() {
        let mut cpu = CPU::new();
        /*
         * LDA #$0F
         * ASL
         * STA $10
         * ASL $10
         * LDA $10
         *
         * reg_a should be 15 * 4 = 60
         */

        cpu.load_and_run(vec![
            0xa9, 0x0f, 0x0a, 0x85, 0x10, 0x06, 0x10, 0xa5, 0x10, 0x00,
        ]);

        assert_eq!(cpu.reg_a, 0x3c);
    }
}
