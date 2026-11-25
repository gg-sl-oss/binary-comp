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


def test_map_skip_matches_whole_path_components(tmp_path):
    _touch(tmp_path, "src/map/all.cpp", "src/bitmap/draw.cpp", "src/legacy/map/old.cpp", "src/map2/x.cpp")

    def found(map_skip):
        return sorted(
            p[len(str(tmp_path)) + 1:]
            for p in iter_source_files([str(tmp_path)], C_SOURCE_EXTENSIONS, map_skip=map_skip)
        )

    # "map" used to skip src/bitmap too, because it was a substring test.
    assert found("map") == ["src/bitmap/draw.cpp", "src/map2/x.cpp"]
    assert found("legacy/map") == ["src/bitmap/draw.cpp", "src/map/all.cpp", "src/map2/x.cpp"]


def test_source_excludes_can_name_a_directory(tmp_path):
    _touch(tmp_path, "src/gen/a.cpp", "src/gen/sub/b.cpp", "src/generated.cpp", "src/keep.cpp")

    found = list(iter_source_files(
        [str(tmp_path / "src")],
        C_SOURCE_EXTENSIONS,
        source_excludes=[str(tmp_path / "src" / "gen")],
    ))
    # Excluding src/gen leaves src/generated.cpp alone.
    assert found == [str(tmp_path / "src" / "generated.cpp"), str(tmp_path / "src" / "keep.cpp")]
