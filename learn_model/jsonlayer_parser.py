import yaml
import re
import json
from datetime import date, datetime

class ComplexEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)


def parse_main(tree_string):
    def init_string(string):
        string_list=string.split('\n')
        result=''
        for i in range(len(string_list)):
            if not string_list[i].startswith('\t'):
                result+=' '+string_list[i]
            elif i!=0:
                result+='\n'+string_list[i]
            else:
                result=string_list[i]
        return result
    def encode_char(char):
        return f"\\u{ord(char):04x}" if ord(char) > 126 else char
    def replace_last_tab(line):
        pattern = re.compile(r'^(\t+)([^\t]*)')
        replaced_line = pattern.sub(lambda match: match.group(1)[:-1] + '- ' + match.group(2) , line)
        return replaced_line
    def parse_tree(tree):
        if type(tree)!=dict:
            return tree
        list_key=list(tree.keys())[0]
        if list_key=='array':
            if tree['array']==None:
                return []
            arr=[parse_tree(j) for j in tree['array']]
            return arr
        elif list_key=='object':
            d={}
            for member in tree['object']:
                key=''
                value_type=''
                for i in member['member']:
                    keys=list(i.keys())[0]
                    try:
                        if 'key' in keys:
                            key=i['key']
                        elif 'number' in keys or 'array' in keys or 'object' in keys or 'string' in keys or 'value' in keys:
                            value_type=keys
                            value=i
                        elif 'number' in keys:
                            value_type='value.number'
                            value={'value.number':i['number']}
                    except:
                        pass
                if value_type=='array' or value_type=='object':
                    d[key]=parse_tree(value)
                # elif value_type=='value.string' or value_type=='string':
                elif 'string' in value_type:
                    d[key]=str(value[value_type])
                elif 'number' in value_type:
                    d[key]=int(value[value_type])
                elif value_type=='value.false':
                    d[key]=False
                elif value_type=='value.true':
                    d[key]=True
                elif value_type=='value.null':
                    d[key]=None
            return d
    a=''
    c=''
    tree_string=init_string(tree_string)
    for i in tree_string.split('\n'):
        a+=replace_last_tab(i)+'\n'
    for i in a:
        c+=encode_char(i)
    b=yaml.safe_load(c.replace('\t','  '))
    return "".join((json.dumps(parse_tree(b[0]),cls=ComplexEncoder)).split('\n'))


if __name__ == "__main__":
    tree_string = open('test11.txt','r').read()
    print(parse_main(tree_string))
