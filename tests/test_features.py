from phishguard.features import FEATURE_NAMES, extract_features


def test_feature_vector_length_matches_names():
    assert len(extract_features("https://example.com")) == len(FEATURE_NAMES)


def test_ip_host_and_at_symbol_detected():
    f = dict(zip(FEATURE_NAMES, extract_features("http://user@192.168.1.5/login")))
    assert f["host_is_ip"] == 1.0
    assert f["has_at_symbol"] == 1.0
    assert f["suspicious_word_count"] >= 1


def test_https_flag():
    assert dict(zip(FEATURE_NAMES, extract_features("https://a.com")))["is_https"] == 1.0
    assert dict(zip(FEATURE_NAMES, extract_features("http://a.com")))["is_https"] == 0.0


def test_malformed_url_does_not_crash():
    assert len(extract_features("http://[bad")) == len(FEATURE_NAMES)
