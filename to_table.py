#!/bin/python3
import re
import os
import sys

USAGE = f'USAGE:\n{sys.argv[0]} directory_path {{text|latex}}'


def find_result_line(data):
    search_range_begin = data.find("[SUCCESS]")
    if search_range_begin == -1:
        search_range_begin = data.find("[FAILURE]")
        if search_range_begin == -1:
            print("Failed to find iteration number")
            
    return search_range_begin


def extract_number_of_iters(filepath):
    with open(filepath, 'r') as f:
        data = f.read()

    search_range_begin = find_result_line(data)

    match = re.search(r'\d+', data[search_range_begin:])
    if match:
        iteration_num = int(match.group())
        return iteration_num

    return -1


def extract_attack_number(filename):
    attack_num = -1

    match = re.search(r'_(\d+)\.out$', filename)
    if match:
        attack_num = int(match.group(1))
    
    return attack_num


def add_slash_or_backslash(directory_path):
    if 'posix' in os.name:
        if not directory_path.endswith('/'):
            directory_path += '/'
    else:
        if not directory_path.endswith('\\'):
            directory_path += '\\'

    return directory_path


def table_data_from_files(directory_path):
    directory = os.fsencode(directory_path)
    data = []

    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        attack_num = extract_attack_number(filename)
        iteration_num = extract_number_of_iters(directory_path + filename)
        data.append((attack_num, iteration_num))

    return data


def sort_table_data(data):
    sorted_data = sorted(data, key=lambda x: x[0])
    
    return sorted_data


def data_to_latex_rows(data):
    rows = ''
    for attack_num, iteration_num in data:
        rows += f'''    {attack_num} & {iteration_num} \\\\
    \\hline
'''
    
    return rows
 

def directory_to_latex_table(directory_path):
    directory_path = add_slash_or_backslash(directory_path)
    data = table_data_from_files(directory_path)
    sorted_data = sort_table_data(data)
    rows = data_to_latex_rows(sorted_data)

    latex_table = f'''\\begin{{center}}
\\begin{{tabular}}{{ |c|c| }} 
    \\hline
    Номер атаки & Кількість ітерацій \\\\
    \\hline
{rows}\\end{{tabular}}
\\end{{center}}'''

    return latex_table


def data_to_text_rows(data):
    rows = 'att\titer\n'
    for attack_num, iteration_num in data:
        rows += f'{attack_num}\t{iteration_num}\n'

    return rows


def directory_to_text_table(directory_path):
    directory_path = add_slash_or_backslash(directory_path)
    data = table_data_from_files(directory_path)
    sorted_data = sort_table_data(data)
    table = data_to_text_rows(sorted_data)

    return table


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(USAGE)
        sys.exit(-1)

    directory_path = sys.argv[1]
    table_type = sys.argv[2]

    if table_type == 'text':
        print(directory_to_text_table(directory_path))
    elif table_type == 'latex':
        print(directory_to_latex_table(directory_path))
    else:
        print('Incorrect table type. Choose between \'text\' or \'latex\'.')
