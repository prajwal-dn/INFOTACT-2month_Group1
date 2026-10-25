from src.logger import parse_candump_line

def test_parse_valid_candump():
    line = '(1600000000.123456) can0 100 [8] DE AD BE EF'
    res = parse_candump_line(line)
    assert res is not None
    assert res['can_id'] == '100'

def test_parse_invalid_line():
    assert parse_candump_line('Not a frame') is None
