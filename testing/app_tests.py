import unittest
import json
from app import app

class TestCase(unittest.TestCase):
  def setUp(self):
    app.config['TESTING'] = True
    app.config["TESTING_DATAFILE"] = "testing/testdata.json"
    self.app = app.test_client()

  def tearDown(self):
    pass

  def test_empty_query(self):
    response = self.app.get("/result.json")
    expected = json.loads(open("testing/expectations/noparam.expected").read())
    received = json.loads(response.data)
    self.assertItemsEqual(received,expected)


  def test_select_nonexistent_AS(self):
    received= json.loads(self.app.get("/result.json?ases=AS3320").data)
    expected = json.loads(
"""
{"total": {"fp": "", "index": null, "as_no": "", "nick": "", "cc": "", "p_exit": 0.0, "adv_bw": 0.0, "guard": "", "link": true, "p_guard": 0.0, "p_middle": 0.0, "exit": "", "as_info": "", "cw": 0.0, "as_name": ""}, "results": [], "excluded": null}
"""
    )
    self.assertItemsEqual(received,expected)

  def test_select_AS_by_number(self):
    received = json.loads(self.app.get("/result.json?ases=7922").data)
    expected = json.loads(
      """
      {"total": {"fp": "", "index": null, "as_no": "", "nick": "(total in selection)", "cc": "", "p_exit": 0.0018185999999999999, "adv_bw": 0.005388199999999999, "guard": "", "link": true, "p_guard": 0.0, "p_middle": 0.0034887, "exit": "", "as_info": "", "cw": 0.0017691999999999999, "as_name": ""}, "results": [{"fp": "CE9CC720B9300FC7E041CCC2B749F283AB5EE1C2", "index": 1, "as_no": "AS7922", "nick": "Tornearse", "cc": "US", "p_exit": 0.0018185999999999999, "adv_bw": 0.005388199999999999, "guard": "-", "link": null, "p_guard": 0.0, "p_middle": 0.0034887, "exit": "Exit", "as_info": "AS7922 Comcast Cable Communications, Inc.", "cw": 0.0017691999999999999, "as_name": "Comcast Cable Communications, Inc."}], "excluded": null}
      """)
    self.assertItemsEqual(received,expected)

  def test_select_AS_with_label(self):
    received = json.loads(self.app.get("/result.json?ases=AS7922").data)
    expected = json.loads(
      """
      {"total": {"fp": "", "index": null, "as_no": "", "nick": "(total in selection)", "cc": "", "p_exit": 0.0018185999999999999, "adv_bw": 0.005388199999999999, "guard": "", "link": true, "p_guard": 0.0, "p_middle": 0.0034887, "exit": "", "as_info": "", "cw": 0.0017691999999999999, "as_name": ""}, "results": [{"fp": "CE9CC720B9300FC7E041CCC2B749F283AB5EE1C2", "index": 1, "as_no": "AS7922", "nick": "Tornearse", "cc": "US", "p_exit": 0.0018185999999999999, "adv_bw": 0.005388199999999999, "guard": "-", "link": null, "p_guard": 0.0, "p_middle": 0.0034887, "exit": "Exit", "as_info": "AS7922 Comcast Cable Communications, Inc.", "cw": 0.0017691999999999999, "as_name": "Comcast Cable Communications, Inc."}], "excluded": null}
      """)
    self.assertItemsEqual(received,expected)

  def test_limit_dataset_size(self):
    received = json.loads(self.app.get("/result.json?top=5").data)
    self.assertEqual(len(received['results']),5)
    expected = json.loads(open("testing/expectations/top5.expected").read())
    self.assertItemsEqual(received,expected)

if __name__ == '__main':
  unittest.main()
