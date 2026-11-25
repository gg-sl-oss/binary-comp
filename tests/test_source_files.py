from __future__ import annotations

from binary_comp.source.functions import C_SOURCE_EXTENSIONS, iter_source_files, source_object_name


def _touch(root, *names):
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")


def test_iter_source_files_walks_in_sorted_order_with_extension_filter(tmp_path):
    _touch(tmp_path, "zeta/b.cpp", "alpha/a.c", "alpha/notes.txt", "top.C", "upper.CPP")

    found = [p[len(str(tmp_path)) + 1:] for p in iter_source_files([str(tmp_path)], C_SOURCE_EXTENSIONS)]
    assert found == ["top.C", "alpha/a.c", "zeta/b.cpp"]

    any_case = [p[len(str(tmp_path)) + 1:] for p in iter_source_files([str(tmp_path)], (".cpp",), ignore_case=True)]
    assert any_case == ["upper.CPP", "zeta/b.cpp"]


def test_iter_source_files_honours_map_skip_and_excludes(tmp_path):
    _touch(tmp_path, "map/all.cpp", "src/keep.cpp", "src/generated.cpp")

    found = list(iter_source_files(
        [str(tmp_path), str(tmp_path / "missing")],
        C_SOURCE_EXTENSIONS,
        map_skip="map",
        source_excludes=[str(tmp_path / "src" / "generated.cpp")],
    ))
    assert found == [str(tmp_path / "src" / "keep.cpp")]


def test_source_object_name():
    assert source_object_name("src/ui/door.cpp") == "door.obj"
