import subprocess
import re
import sys
import os
import argparse

PAGE_SIZE = 4096
LEVEL_NAMES = ['PGD', 'P4D', 'PUD', 'PMD', 'PTE']

def get_pid_by_name(process_name):
    try:
        pid = subprocess.check_output(["pgrep", "-n", process_name]).decode().strip()
        return pid
    except subprocess.CalledProcessError:
        print(f"Процесс '{process_name}' не найден.")
        sys.exit(1)

def get_segment_range(pid, segment_name="[heap]"):
    try:
        maps_output = subprocess.check_output(["cat", f"/proc/{pid}/maps"]).decode()
    except Exception as e:
        print(f"Ошибка при чтении /proc/{pid}/maps: {e}")
        sys.exit(1)

    for line in maps_output.splitlines():
        if segment_name in line:
            match = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
            if match:
                return int(match.group(1), 16), int(match.group(2), 16)

    print(f"Сегмент '{segment_name}' не найден у процесса {pid}")
    sys.exit(1)


def run_pagemap(pid, start, end):
    cmd = ["sudo", "../pagemap/pagemap", str(pid), f"0x{start:x}", f"0x{end:x}"]
    try:
        output = subprocess.check_output(cmd).decode().splitlines()
        return output
    except subprocess.CalledProcessError as e:
        print(f"Ошибка при запуске pagemap: {e}")
        sys.exit(1)

def parse_pagemap_output(lines):
    entries = []
    for line in lines:
        if 'present 1' not in line:
            continue
        match = re.match(r'^(0x[0-9a-f]+)\s+: pfn ([0-9a-f]+)', line)
        if match:
            va = int(match.group(1), 16)
            pfn = int(match.group(2), 16)
            pa = pfn * PAGE_SIZE
            entries.append((va, pa))
    return entries

def get_page_indices(va):
    return {
        'pgd': (va >> 48) & 0x1FF,
        'p4d': (va >> 39) & 0x1FF,
        'pud': (va >> 30) & 0x1FF,
        'pmd': (va >> 21) & 0x1FF,
        'pte': (va >> 12) & 0x1FF,
        'offset': va & 0xFFF,
    }

def build_page_table(entries):
    page_table = {}
    for va, pa in entries:
        idx = get_page_indices(va)
        pgd = page_table.setdefault(idx['pgd'], {})
        p4d = pgd.setdefault(idx['p4d'], {})
        pud = p4d.setdefault(idx['pud'], {})
        pmd = pud.setdefault(idx['pmd'], {})
        pte = pmd.setdefault(idx['pte'], pa)
    return page_table



def print_table_structure(table, level=0):
    indent = "  " * level
    for key, val in table.items():
        level_name = LEVEL_NAMES[level] if level < len(LEVEL_NAMES) else f"Level {level}"
        if isinstance(val, dict):
            print(f"{indent}{level_name} Index {key:03x}")
            print_table_structure(val, level + 1)
        else:
            print(f"{indent}{level_name} Index {key:03x} → PA 0x{val:012x}")


def draw_ascii_tree(table, level=0, prefix=""):
    """Рекурсивно рисует дерево таблиц трансляции в ASCII."""
    level_name = LEVEL_NAMES[level] if level < len(LEVEL_NAMES) else f"Level{level}"

    last_key = list(table.keys())[-1]
    for idx, key in enumerate(sorted(table.keys())):
        is_last = (key == last_key)
        connector = "└──" if is_last else "├──"
        next_prefix = prefix + ("    " if is_last else "│   ")

        if isinstance(table[key], dict):
            print(f"{prefix}{connector} {level_name}[{key:03x}]")
            draw_ascii_tree(table[key], level + 1, next_prefix)
        else:
            print(f"{prefix}{connector} PTE[{key:03x}] → PA 0x{table[key]:012x}")




def main():
    parser = argparse.ArgumentParser(description="Построение таблиц трансляции страниц для процесса.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-n", "--name", help="Имя процесса")
    group.add_argument("-p", "--pid", help="PID процесса")

    parser.add_argument("-s", "--segment", default="heap", help="Имя сегмента (по умолчанию: heap)")

    args = parser.parse_args()

    if args.name:
        pid = get_pid_by_name(args.name)
        print(f"Найден PID процесса '{args.name}': {pid}")
    else:
        pid = args.pid
        print(f"Используется указанный PID: {pid}")

    # Подготовим имя сегмента
    seg = args.segment
    if not seg.startswith("["):
        seg = f"[{seg}]"

    start, end = get_segment_range(pid, seg)
    print(f"Диапазон {seg}: 0x{start:x} - 0x{end:x}")

    print("Запуск pagemap...")
    pagemap_lines = run_pagemap(pid, start, end)

    print("Парсинг данных pagemap...")
    entries = parse_pagemap_output(pagemap_lines)

    print(f"Найдено {len(entries)} отображённых страниц")

    print("Построение таблиц трансляции...")
    page_table = build_page_table(entries)

    print("ASCII-визуализация таблиц трансляции:")
    draw_ascii_tree(page_table)


if __name__ == "__main__":
    main()
