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
        self.nick = None
        self.fp = None
        self.link = None
        self.exit = None
        self.guard = None
        self.cc = None
        self.as_no = None
        self.as_name = None
        self.as_info = None

    def __getitem__(self,prop):
      getattr(self,prop)

    def __setitem__(self,prop,val):
      setattr(self,prop,val)

    def jsonify(self):
      return self.__dict__

class ResultEncoder(json.JSONEncoder):
  def default(self,obj):
    if isinstance(obj,Result):
      return obj.__dict__
    return json.JSONEncoder.default(self,obj)

