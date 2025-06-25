

MVI_CODES = {
    "A": 0x3E,
    "B": 0x06,
    "C": 0x0E,
    "D": 0x16,
    "H": 0x26,
    "L": 0x2E,
}

LXI_CODES = {
    "B": 0x01,
    "D": 0x11,
    "H": 0x21,
}

ADD_CODES = {
    "ADD B": 0x80,
    "ADD C": 0x81,
    "ADD D": 0x82,
    "ADD E": 0x83,
    "ADD H": 0x84,
    "ADD L": 0x85,
    "ADD M": 0x86,
    "ADD A": 0x87,
    "ADC B": 0x88,
    "ADC C": 0x89,
    "ADC D": 0x8A,
    "ADC E": 0x8B,
    "ADC H": 0x8C,
    "ADC L": 0x8D,
    "ADC M": 0x8E,
    "ADC A": 0x8F,
}
ANA_CODES = {
    "ANA B": 0xA0,
    "ANA C": 0xA1,
    "ANA D": 0xA2,
    "ANA E": 0xA3,
    "ANA H": 0xA4,
    "ANA L": 0xA5,
    "ANA M": 0xA6,
    "ANA A": 0xA7,
}


ADC_CODES = {
    "ADC B": 0x88,
    "ADC C": 0x89,
    "ADC D": 0x8A,
    "ADC E": 0x8B,
    "ADC H": 0x8C,
    "ADC L": 0x8D,
}


JUMP_CODES = {
    "JNZ": 0xC2,
    "JNC": 0xD2,
    "JPO": 0xE2,
}
DCR_CODES = {
    "DCR B": 0x05,
    "DCR C": 0x0D,
    "DCR D": 0x15,
    "DCR E": 0x1D,
    "DCR H": 0x25,
    "DCR L": 0x2D,
    "DCR M": 0x35,
    "DCR A": 0x3D,
}

ORA_CODES = {
    "ORA B": 0xB0,
    "ORA C": 0xB1,
    "ORA D": 0xB2,
    "ORA E": 0xB3,
    "ORA H": 0xB4,
    "ORA L": 0xB5,
    "ORA M": 0xB6,
    "ORA A": 0xB7,
}

XRA_CODES = {
    "XRA B": 0xA8,
    "XRA C": 0xA9,
    "XRA D": 0xAA,
    "XRA E": 0xAB,
    "XRA H": 0xAC,
    "XRA L": 0xAD,
    "XRA M": 0xAE,
    "XRA A": 0xAF,
}

CMP_CODES = {
    "CMP B": 0xB8,
    "CMP C": 0xB9,
    "CMP D": 0xBA,
    "CMP E": 0xBB,
    "CMP H": 0xBC,
    "CMP L": 0xBD,
    "CMP M": 0xBE,
    "CMP A": 0xBF,
}


SINGLE_BYTE_IMMEDIATE_OPCODES = {
    "ADI": 0xC6,
    "ACI": 0xCE,
    "SUI": 0xD6,
    "SBI": 0xDE,
    "ANI": 0xE6,
    "XRI": 0xEE,
    "ORI": 0xF6,
    "CPI": 0xFE,
}

REGISTER_CODES = {
    'B': 0,
    'C': 1,
    'D': 2,
    'E': 3,
    'H': 4,
    'L': 5,
    'M': 6,
    'A': 7
}


# === OPCODES ===
MOV_OPCODES = {
    "MOV A,B": 0x78, "MOV A,C": 0x79, "MOV A,D": 0x7A, "MOV A,E": 0x7B,
    "MOV A,H": 0x7C, "MOV A,L": 0x7D, "MOV A,M": 0x7E,
    "MOV B,A": 0x47, "MOV C,A": 0x4F, "MOV D,A": 0x57, "MOV E,A": 0x5F,
    "MOV H,A": 0x67, "MOV L,A": 0x6F, "MOV M,A": 0x77,
    "MOV B,B": 0x40, "MOV C,C": 0x49  
}

MVI_CODES = {
    "A": 0x3E, "B": 0x06, "C": 0x0E, "D": 0x16, "E": 0x1E, "H": 0x26, "L": 0x2E, "M": 0x36
}

MVI_OPCODES = MVI_CODES

ADD_CODES = {
    "ADD A": 0x87, "ADD B": 0x80, "ADD C": 0x81, "ADD D": 0x82,
    "ADD E": 0x83, "ADD H": 0x84, "ADD L": 0x85, "ADD M": 0x86
}

ADC_CODES = {
    "ADC A": 0x8F, "ADC B": 0x88, "ADC C": 0x89, "ADC D": 0x8A,
    "ADC E": 0x8B, "ADC H": 0x8C, "ADC L": 0x8D, "ADC M": 0x8E
}

SINGLE_BYTE_IMMEDIATE_OPCODES = {
    "SUI": 0xD6, "CPI": 0xFE, "ANI": 0xE6, "ORI": 0xF6, "XRI": 0xEE
}

ORA_CODES = {
    "ORA A": 0xB7, "ORA B": 0xB0, "ORA C": 0xB1, "ORA D": 0xB2,
    "ORA E": 0xB3, "ORA H": 0xB4, "ORA L": 0xB5, "ORA M": 0xB6
}

XRA_CODES = {
    "XRA A": 0xAF, "XRA B": 0xA8, "XRA C": 0xA9, "XRA D": 0xAA,
    "XRA E": 0xAB, "XRA H": 0xAC, "XRA L": 0xAD, "XRA M": 0xAE
}

CMP_CODES = {
    "CMP A": 0xBF, "CMP B": 0xB8, "CMP C": 0xB9, "CMP D": 0xBA,
    "CMP E": 0xBB, "CMP H": 0xBC, "CMP L": 0xBD, "CMP M": 0xBE
}

ANA_CODES = {
    "ANA A": 0xA7, "ANA B": 0xA0, "ANA C": 0xA1, "ANA D": 0xA2,
    "ANA E": 0xA3, "ANA H": 0xA4, "ANA L": 0xA5, "ANA M": 0xA6
}

LXI_CODES = {
    "B": 0x01, "D": 0x11, "H": 0x21, "SP": 0x31
}

JUMP_CODES = {
    "JMP": 0xC3, "JC": 0xDA, "JNC": 0xD2, "JZ": 0xCA, "JNZ": 0xC2
}

INR_OPCODES = {
    "A": 0x3C, "B": 0x04, "C": 0x0C, "D": 0x14, "E": 0x1C, "H": 0x24, "L": 0x2C, "M": 0x34
}

DCR_OPCODES = {
    "A": 0x3D, "B": 0x05, "C": 0x0D, "D": 0x15, "E": 0x1D, "H": 0x25, "L": 0x2D, "M": 0x35
}

INX_OPCODES = {
    'B': 0x03,
    'D': 0x13,
    'H': 0x23,
    'SP': 0x33,
}

INR_OPCODES = {reg: 0x04 + (code << 3) for reg, code in REGISTER_CODES.items()}
DCR_OPCODES = {reg: 0x05 + (code << 3) for reg, code in REGISTER_CODES.items()}
MVI_OPCODES = {reg: 0x06 + (code << 3) for reg, code in REGISTER_CODES.items()}

def assemble_line(line, labels=None):
    line = line.strip().upper()

    if not line or line.startswith(';') or line.endswith(':'):
        return b''

    # Імедіатні інструкції на 2 байти (OP value)
    for mnemonic, opcode in SINGLE_BYTE_IMMEDIATE_OPCODES.items():
        if line.startswith(mnemonic + " "):
            value_str = line[len(mnemonic) + 1:]
            try:
                value = int(value_str, 0)
            except ValueError:
                raise ValueError(f"Невірне імедіат значення: {value_str}")
            if not 0 <= value <= 0xFF:
                raise ValueError(f"Імедіат значення має бути в межах 0–255: {value}")
            return bytes([opcode, value])

    # MOV dst,src
    if line.startswith("MOV "):
        operands = line[4:].split(',')
        if len(operands) != 2:
            raise ValueError("Невірний синтаксис MOV")
        key = f"MOV {operands[0].strip()},{operands[1].strip()}"
        if key in MOV_OPCODES:
            return bytes([MOV_OPCODES[key]])
        else:
            raise ValueError(f"Невідома MOV інструкція: {key}")

    # DB
    if line.startswith("DB"):
        data_part = line[2:].strip()
        values = [v.strip() for v in data_part.split(',')]
        result_bytes = bytearray()
        for val in values:
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                if len(val[1:-1]) != 1:
                    raise ValueError("DB: можна записувати лише один символ у лапках")
                result_bytes.append(ord(val[1:-1]))
            else:
                result_bytes.append(int(val, 0))
        return bytes(result_bytes)

    #INX
    if line.startswith("INX "):
        reg_pair = line[4:].strip()
        if reg_pair not in INX_OPCODES:
            raise ValueError(f"Невідома пара регістрів для INX: {reg_pair}")
        return bytes([INX_OPCODES[reg_pair]])

    #OUT
    if line.startswith("OUT "):
        port_str = line[4:].strip()
        try:
            port = int(port_str, 0)
        except ValueError:
            raise ValueError(f"Невірний порт для OUT: {port_str}")
        if not 0 <= port <= 0xFF:
            raise ValueError("Порт має бути в межах 0-255")
        return bytes([0xD3, port])

    #IN
    if line.startswith("IN "):
        port_str = line[3:].strip()
        try:
            port = int(port_str, 0)
        except ValueError:
            raise ValueError(f"Невірний порт для IN: {port_str}")
        if not 0 <= port <= 0xFF:
            raise ValueError("Порт має бути в межах 0-255")
        return bytes([0xDB, port])

    #MVI
    if line.startswith("MVI "):
        try:
            reg, value_str = line[4:].split(',')
            reg = reg.strip()
            value_str = value_str.strip()

            if (value_str.startswith('"') and value_str.endswith('"')) or \
            (value_str.startswith("'") and value_str.endswith("'")):
                char = value_str[1:-1]
                if len(char) != 1:
                    raise ValueError("Можна записувати лише один символ у лапках")
                value = ord(char)  # ASCII код символу
            else:
                value = int(value_str, 0)

            if reg not in MVI_OPCODES:
                raise ValueError(f"Невідомий регістр: {reg}")
            if not 0 <= value <= 0xFF:
                raise ValueError("Імедіат значення має бути в межах 0–255")

            return bytes([MVI_OPCODES[reg], value])
        except Exception:
            raise ValueError("Невірний синтаксис MVI")

    #LXI
    if line.startswith("LXI "):
        try:
            rp, value_str = line[4:].split(',')
            rp = rp.strip()
            value_str = value_str.strip()

            if rp not in LXI_CODES:
                raise ValueError(f"Невідомий регістр-пара: {rp}")

            if labels and value_str.upper() in labels:
                addr = labels[value_str.upper()]
            else:
                addr = int(value_str, 0)

            if not 0 <= addr <= 0xFFFF:
                raise ValueError("16-бітне значення повинно бути в межах 0–65535")

            lo = addr & 0xFF
            hi = (addr >> 8) & 0xFF
            return bytes([LXI_CODES[rp], lo, hi])
        except Exception:
            raise ValueError("Невірний синтаксис LXI")




    # ALU регістрові (ADD, ADC, ANA, ORA, XRA, CMP)
    for group in (ADD_CODES, ADC_CODES, ANA_CODES, ORA_CODES, XRA_CODES, CMP_CODES):
        if line in group:
            return bytes([group[line]])

    # INR reg
    if line.startswith("INR "):
        reg = line[4:].strip()
        if reg in INR_OPCODES:
            return bytes([INR_OPCODES[reg]])
        else:
            raise ValueError(f"Невідомий регістр INR: {reg}")

    # DCR reg
    if line.startswith("DCR "):
        reg = line[4:].strip()
        if reg in DCR_OPCODES:
            return bytes([DCR_OPCODES[reg]])
        else:
            raise ValueError(f"Невідомий регістр DCR: {reg}")

    # Jumps (JMP, JC, JNC, JZ, JNZ etc)
    for mnemonic, opcode in JUMP_CODES.items():
        if line.startswith(mnemonic + " "):
            target = line[len(mnemonic) + 1:].strip()
            if labels and target in labels:
                addr = labels[target]
            else:
                try:
                    addr = int(target, 0)
                except ValueError:
                    raise ValueError(f"Невідома мітка або адреса: {target}")
            lo = addr & 0xFF
            hi = (addr >> 8) & 0xFF
            return bytes([opcode, lo, hi])

    raise ValueError(f"Невідома або непідтримувана інструкція: {line}")
def get_instruction_size(cmd):
    # Розміри команд, які ти використовуєш
    two_byte_cmds = {"MVI", "ADI", "SUI", "INR", "DCR"}  # приклад
    three_byte_cmds = {"LXI", "LDA", "STA", "JMP", "JC", "JNC", "JZ", "JNZ"}

    if cmd in two_byte_cmds:
        return 2
    if cmd in three_byte_cmds or cmd in JUMP_CODES:
        return 3
    # Всі інші – 1 байт
    return 1
def assemble_program(lines):
    labels = {}
    addr = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(';'):
            continue

        if ':' in stripped:
            label_part, rest = stripped.split(':', 1)
            label = label_part.strip().upper()
            labels[label] = addr
            stripped = rest.strip()  
            if not stripped:
                continue  

        cmd = stripped.upper().split()[0]
        if cmd == "MVI" or cmd == "MOV" or cmd == "ADD" or cmd == "ADC":
            if cmd == "MVI":
                addr += 2
            else:
                addr += 1
        elif cmd == "LXI" or cmd == "LDA" or cmd in JUMP_CODES:
            addr += 3
        elif cmd == "DB":
            data_part = stripped[2:].strip()
            values = [v.strip() for v in data_part.split(',')]
            addr += len(values)
        else:
            addr += 1

    bytecode = b''
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(';'):
            continue

        if ':' in stripped:
            _, rest = stripped.split(':', 1)
            stripped = rest.strip()
            if not stripped:
                continue

        try:
            bytecode += assemble_line(stripped, labels=labels)
        except Exception as e:
            print(f"[!] Помилка: {e} у рядку '{line}'")
    return bytecode

