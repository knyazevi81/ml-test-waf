import json
import urllib.parse

def unquote(text):
    k = 0
    uq_prev = text
    while k < 100:
        uq = urllib.parse.unquote_plus(uq_prev)
        if uq == uq_prev:
            break
        else:
            uq_prev = uq
    return uq_prev

def remove_new_line(text):
    text = text.strip()
    text = ' '.join(text.splitlines())
    return text

def remove_multiple_whitespaces(text):
    return ' '.join(text.split())

def clean_pattern(pattern):
    pattern = unquote(pattern)
    pattern = remove_new_line(pattern)
    pattern = pattern.lower()
    pattern = remove_multiple_whitespaces(pattern)
    return pattern

def prepare_ecml(x):
    out = {
        'pattern': clean_pattern(x['request']),
        'type': {
            'Valid': 'valid',
            'XSS': 'xss',
            'SqlInjection': 'sqli',
            'PathTransversal': 'path-traversal',
            'OsCommanding': 'cmdi'
        }.get(x['type'], 'unknown')
    }
    return out

def prepare_custom(x):
    return {
        'pattern': clean_pattern(x['payload']),
        'type': 'valid' if x['attack_type'] == 'norm' else x['attack_type']
    }

def prepare_xss(x):
    return {
        'pattern': clean_pattern(x['Sentence']),
        'type': 'xss' if x['Label'] == 1 else 'valid'
    }

if __name__ == '__main__':
    with open('ParsedToJson/ECML.json', 'r') as f:
        ecml = json.load(f)
    with open('ParsedToJson/HTTPParams.json', 'r') as f:
        custom = json.load(f)
    with open('ParsedToJson/xss.json', 'r') as f:
        xss = json.load(f)

    ecml = list(map(prepare_ecml, ecml))
    custom = list(map(prepare_custom, custom))
    xss = list(map(prepare_xss, xss))

    with open('Cleaned/ecml_clean.json', 'w') as f:
        json.dump(ecml, f)
    with open('Cleaned/HTTPParams_clean.json', 'w') as f:
        json.dump(custom, f)
    with open('Cleaned/xss_clean.json', 'w') as f:
        json.dump(xss, f)
    complete_clean = ecml+custom+xss
    with open('complete_clean.json', 'w') as f:
        json.dump(complete_clean, f)
    