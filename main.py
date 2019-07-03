import re
import sys

import yaml
import cmd2
import json
from prettytable import PrettyTable
import httplib

# file = "/media/ubuntu/work/cmi/user/src/main/resources/policy.yml"
stream = file('../user/src/main/resources/policy.yml', 'r')
url = "http://10.12.3.87:8088/ws/user/v2/api-docs"
yaml_info = yaml.load(stream, Loader=yaml.BaseLoader)

all_role = ["sdm_op", "cust_op", "info_op", "pa_op"]


def write_yaml():
    yaml.safe_dump(yaml_info, file('../user/src/main/resources/policy.yml', 'w'), sort_keys=False)


def load_policy():
    return yaml_info.get('policy')


def load_allow():
    return yaml_info.get('allow')


def parse_url(data):
    rs = []
    for k, v in data['paths'].items():
        for m in v.keys():
            rs.append({
                "path": re.sub(u"{.*?}", "{}", k),
                "method": m,
                "summary": v[m]['summary'][:50]
            })
    return rs


def get_all_url():
    conn = httplib.HTTPConnection("10.12.3.87", 8088)
    conn.request("GET", "/ws/user/v2/api-docs")
    r1 = conn.getresponse()
    rs = r1.read()
    conn.close()
    rs = json.loads(rs)
    return rs


class MyApp(cmd2.Cmd):
    prompt = 'policy:>'

    def do_list_policy(self, line):
        self.poutput(json.dumps(load_policy(), indent=4))

    def do_list_path(self, line):
        self.poutput(json.dumps([_.get('path') for _ in load_policy()], indent=4))

    def do_list_key_info(self, line):
        x = PrettyTable()
        x.field_names = ["path", "method", "roles"]
        x.align["path"] = "l"
        x.align["method"] = "l"
        x.align["roles"] = "l"
        for v in [(_.get('path'), _.get('method'), ",".join(_.get('roles'))) for _ in load_policy()]:
            if not line:
                x.add_row(v)
            elif line in v[0]:
                x.add_row(v)
        self.poutput(x)

    def do_list_all_url(self, line):
        rs = get_all_url()
        x = PrettyTable()
        x.field_names = ["path", "method", "summary"]
        x.align["path"] = "l"
        x.align["method"] = "l"
        x.align["summary"] = "l"
        if not line:
            for v in parse_url(rs):
                x.add_row((v['path'], v['method'], v['summary']))
        if line == "allow":
            allows = load_allow()
            for av in allows:
                for uv in parse_url(rs):
                    if av in uv['path']:
                        x.add_row((uv['path'], uv['method'], uv['summary']))
        if line == "policy":
            allows = load_allow()
            allow_url = []
            for av in allows:
                for uv in parse_url(rs):
                    if av in uv['path']:
                        allow_url.append(uv)

            allow_url_key = [_['path'] + "-" + _['method'] for _ in allow_url]
            for uv in parse_url(rs):
                if uv['path'] + "-" + uv['method'] not in allow_url_key:
                    x.add_row((uv['path'], uv['method'], uv['summary']))

        if line == "unassigned":
            no_allow = []
            allows = load_allow()
            allow_url = []
            for av in allows:
                for uv in parse_url(rs):
                    if av in uv['path']:
                        allow_url.append(uv)

            allow_url_key = [_['path'] + "-" + _['method'] for _ in allow_url]
            for uv in parse_url(rs):
                if uv['path'] + "-" + uv['method'] not in allow_url_key:
                    no_allow.append(uv)

            policy = load_policy()
            for uv in no_allow:
                if uv['path'] + "-" + uv['method'] not in [pv['path'] + "-" + pv['method'] for pv in policy]:
                    x.add_row((uv['path'], uv['method'], uv['summary']))

        self.poutput(x)

    def complete_list_all_url(self, text, line, begidx, endidx):
        v = ["policy", "allow", "unassigned"]
        if not text:
            completions = v
        else:
            completions = [f for f in v if f.startswith(text)]
        return completions

    def do_assign_all_unassigned_url(self, line):
        rs = get_all_url()
        no_allow = []
        allows = load_allow()
        allow_url = []
        for av in allows:
            for uv in parse_url(rs):
                if av in uv['path']:
                    allow_url.append(uv)

        allow_url_key = [_['path'] + "-" + _['method'] for _ in allow_url]
        for uv in parse_url(rs):
            if uv['path'] + "-" + uv['method'] not in allow_url_key:
                no_allow.append(uv)

        policy = load_policy()
        for uv in no_allow:
            if uv['path'] + "-" + uv['method'] not in [pv['path'] + "-" + pv['method'] for pv in policy]:
                policy.append({
                    "path": uv['path'],
                    "method": uv['method'],
                    "roles": ["sdm_op", "cust_op", "info_op", "pa_op"]
                })
        x = PrettyTable()
        x.field_names = ["path", "method", "roles"]
        x.align["path"] = "l"
        x.align["method"] = "l"
        x.align["roles"] = "l"
        for v in [(_.get('path'), _.get('method'), ",".join(_.get('roles'))) for _ in yaml_info.get('policy')]:
            x.add_row(v)
        self.poutput(x)

    def do_write(self, line):
        write_yaml()
        self.poutput("ok")

    def do_dump(self, line):
        self.poutput(yaml.safe_dump(yaml_info, sort_keys=False))


if __name__ == '__main__':
    app = MyApp()
    sys.exit(app.cmdloop())
