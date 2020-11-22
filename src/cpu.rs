pub struct CPU {
    pub reg_a: u8,
    pub reg_x: u8,
    pub status: u8,
    pub pc: u16,
}

impl CPU {
    pub fn new() -> Self {
        CPU {
            reg_a: 0,
            reg_x: 0,
            status: 0,
            pc: 0,
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

    fn lda_imm(&mut self, value: u8) {
        self.reg_a = value;
        self.update_zn(self.reg_a);
    }

    fn tax(&mut self) {
        self.reg_x = self.reg_a;
        self.update_zn(self.reg_x);
    }

    fn inx(&mut self) {
        self.reg_x = self.reg_x.wrapping_add(1);
        self.update_zn(self.reg_x);
    }

    pub fn interpret(&mut self, program: Vec<u8>) {
        self.pc = 0;

        loop {
            let opscode = program[self.pc as usize];
            self.pc += 1;

            match opscode {
                0xA9 => {
                    let param = program[self.pc as usize];
                    self.pc += 1;
                    self.lda_imm(param);
                }

                0xAA => self.tax(),

                0xE8 => self.inx(),

                0x00 => return,

                _ => todo!(),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::CPU;

    #[test]
    fn test_lda_imm_tax_pos() {
        let mut cpu = CPU::new();

        for value in 0x01..0x80 {
            let mut v = Vec::new();
            v.push(0xa9);
            v.push(value);
            v.push(0x00);
            cpu.interpret(v);

            /* value checking */
            assert_eq!(cpu.reg_a, value);
            /* status checking: Z should be 0 and N should be 0 */
            assert!(cpu.status & 0b10000010 == 0b00000000);

            cpu.interpret(vec![0xaa, 0x00]);
            assert_eq!(cpu.reg_x, cpu.reg_a);
            assert!(cpu.status & 0b10000010 == 0b00000000);
        }
    }

    #[test]
    fn test_lda_imm_tax_zero() {
        let mut cpu = CPU::new();
        cpu.interpret(vec![0xa9, 0x00, 0x00]);
        assert!(cpu.status & 0b00000010 == 0b00000010);

        cpu.interpret(vec![0xaa, 0x00]);
        assert_eq!(cpu.reg_x, cpu.reg_a);
        assert!(cpu.status & 0b00000010 == 0b00000010);
    }

    #[test]
    fn test_lda_imm_tax_neg() {
        let mut cpu = CPU::new();

        for value in 0x080..=0xFF {
            let mut v = Vec::new();
            v.push(0xa9);
            v.push(value);
            v.push(0x00);
            cpu.interpret(v);

            /* value checking */
            assert_eq!(cpu.reg_a, value);
            /* status checking: Z should be 0 and N should be 1 */
            assert!(cpu.status & 0b10000010 == 0b10000000);

            cpu.interpret(vec![0xaa, 0x00]);
            assert_eq!(cpu.reg_x, cpu.reg_a);
            assert!(cpu.status & 0b10000010 == 0b10000000);
        }
    }

    #[test]
    fn test_inx_overflow() {
        let mut cpu = CPU::new();
        cpu.reg_x = 0xff;
        cpu.interpret(vec![0xe8, 0xe8, 0x00]);
        assert_eq!(cpu.reg_x, 1);
    }

    #[test]
    fn test_target() {
        let mut cpu = CPU::new();
        cpu.interpret(vec![0xa9, 0xc0, 0xaa, 0xe8, 0x00]);

        assert_eq!(cpu.reg_x, 0xc1)
    }
}
