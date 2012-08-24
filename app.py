import os
import re
import compass
from flask import Flask, request, redirect, render_template, url_for

app = Flask(__name__)

class Opt(object):
    def __init__(self):
        self.by_as = False
        self.family = None
        self.by_country = False
        self.ases = None
        self.country = None
        self.top = -1
        self.short = None 
        self.links = None 
        self.guards_only = None
        self.inactive = False 
        self.almost_fast_exits_only = None 
        self.exits_only = False
        self.download = None 
        self.fast_exits_only = False
        self.fast_exits_only_any_network = False
        self.all_relays = False

class Result():
    def __init__(self):
        self.cw = None
        self.adv_bw = None
        self.p_guard = None
        self.p_exit = None
        self.p_middle = None
        self.nick = None
        self.fp = None
        self.link = None
        self.exit = None
        self.guard = None
        self.cc = None
        self.as_no = None
        self.as_name = None

def parse(output_string, grouping=False, sort_key=None):
    results = []
    sorted_results = {}

    for id, line in enumerate(output_string):
        # skip headings
        if id == 0: continue

        result = Result()
        values = line.split()

        """
        This is a super weird hack. When we group by country or AS, the
        nickname is replaced with '(x relays)' which when split() creates
        ['(x','relays)']. I need to join this again and then left shift all
        the elements and delete the last element in the list.
        """
        if grouping:
            values[5] = "%s %s" % (values[5], values[6])
            for id in xrange(7, len(values)):
                values[id-1] = values[id]
            del values[id]
            
        # TODO: change inaccurate value of 10
        if len(values) > 10:
            result.cw = values[0]
            result.adv_bw = values[1]
            result.p_guard = values[2]
            result.p_middle = values[3]
            result.p_exit = values[4]
            result.nick = values[5]
            result.fp = values[6]
            result.exit = values[7]
            result.guard = values[8]
            result.cc = values[9]
            result.as_no = values[10]
            result.as_name = ' '.join(values[11:])
            result.as_name = re.sub(r'\([^)]*\)', '', result.as_name)

            if sort_key:
                key = float(getattr(result, sort_key)[:-1])
                if sorted_results.has_key(key):
                    sorted_results[key].append(result)
                else:
                    sorted_results[key] = [result]
            else:
                results.append(result)
    return results if results else sorted_results

@app.route('/')
def index():    
    return render_template('index.html')

@app.route('/result', methods=['GET'])
def result():
    options = Opt()
    sort_key = None
    relays = []
    
    for key, value in request.args.items():
        if key == "top":
            try:
                options.top = int(value)
            except:
                options.top = -1
        elif key == "sort":
            sort_key = value
        elif key in ["country", "ases"]:
            if value:
                setattr(options, key, [value])
            else:
                setattr(options, key, None)
        elif key == "exits":
            setattr(options, value, True)
        else:
            setattr(options, key, value)
    
    stats = compass.RelayStats(options)
    sorted_groups = stats.format_and_sort_groups(stats.relays,
                        by_country=options.by_country,
                        by_as_number=options.by_as,
                        links=options.links)
    output_string = stats.print_groups(sorted_groups, options.top,
                   by_country=options.by_country,
                   by_as_number=options.by_as,
                   short=None,
                   links=None)
    results = parse(output_string, options.by_country or options.by_as, sort_key)
    
    if sort_key:
        for key in sorted(results.iterkeys(), reverse=True):
            for value in results[key]:
                relays.append(value)
    else:
        relays = results
    
    return render_template('result.html', results=relays)
    
if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
