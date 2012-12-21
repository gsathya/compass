import json

def Container(val):
  return json.loads(val)

def NullFn(val):
  return val

def Int(val):
  try:
    return int(val)
  except:
    return None

def Boolean(val):
  if val == True:
    return True

  if val in ("false", "False", "FALSE", "F"):
    return False
  if val in ("true", "True", "TRUE", "T"):
    return True

  return False

class Result():
    WEIGHT_FIELDS = {
    'consensus_weight_fraction': 'cw', 
    'advertised_bandwidth_fraction': 'adv_bw',
    'guard_probability': 'p_guard',
    'middle_probability': 'p_middle',
    'exit_probability': 'p_exit',
    }

    def __init__(self, zero_probs = False):
        self.index = None
        self.cw = 0.0 if zero_probs else None
        self.adv_bw = 0.0 if zero_probs else None
        self.p_guard = 0.0 if zero_probs else None
        self.p_exit = 0.0 if zero_probs else None
        self.p_middle = 0.0 if zero_probs else None
        self.nick = ""
        self.fp = ""
        self.link = ""
        self.exit = ""
        self.guard = ""
        self.cc = ""
        self.as_no = ""
        self.as_name = ""
        self.as_info = ""

    def __getitem__(self,prop):
      getattr(self,prop)

    def __setitem__(self,prop,val):
      setattr(self,prop,val)

    def jsonify(self):
      return self.__dict__

    def printable_fields(self,links=False):
      """
      Return this Result object as a list with the fields in the order
      expected for printing.
      """
      format_str = "%.4f%%|%.4f%%|%.4f%%|%.4f%%|%.4f%%|%s|%s|%s|%s|%s|%s"
      formatted = format_str % ( self.cw, self.adv_bw, self.p_guard, self.p_middle, self.p_exit,
                    self.nick, 
                    "https://atlas.torproject.org/#details/" + self.fp if links else self.fp,
                    self.exit, self.guard, self.cc, self.as_info )
      return formatted.split("|")

class ResultEncoder(json.JSONEncoder):
  def default(self,obj):
    if isinstance(obj,Result):
      return obj.__dict__
    return json.JSONEncoder.default(self,obj)

