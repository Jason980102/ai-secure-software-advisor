from app.services.dependency_parser import parse_requirements


def test_parse_pinned_dependencies():
    content = """
    fastapi==0.95.0
    requests==2.19.0
    numpy==1.24.0
    """

    dependencies = parse_requirements(content)

    assert len(dependencies) == 3
    assert dependencies[0].name == "fastapi"
    assert dependencies[0].version == "0.95.0"
    assert dependencies[1].name == "requests"
    assert dependencies[1].version == "2.19.0"


def test_ignore_comments_and_blank_lines():
    content = """
    # Web framework
    fastapi==0.95.0

    # HTTP client
    requests==2.19.0
    """

    dependencies = parse_requirements(content)

    assert len(dependencies) == 2
    assert dependencies[0].name == "fastapi"
    assert dependencies[1].name == "requests"


def test_ignore_unsupported_requirements():
    content = """
    fastapi>=0.95.0
    requests~=2.31.0
    numpy
    flask==1.0.2
    """

    dependencies = parse_requirements(content)

    assert len(dependencies) == 1
    assert dependencies[0].name == "flask"
    assert dependencies[0].version == "1.0.2"


def test_empty_content():
    dependencies = parse_requirements("")

    assert dependencies == []