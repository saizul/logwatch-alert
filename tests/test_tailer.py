import io
import os
import time

from logwatch_alert.tailer import MAX_LINE, FileTailer, StreamReader


def lines(tailer):
    return [line for _, line in tailer.poll()]


def test_starts_at_end_and_reads_appended_lines(tmp_path, write):
    log = tmp_path / "app.log"
    write(log, "old 1\nold 2\n")
    tailer = FileTailer(str(log))
    assert lines(tailer) == []
    write(log, "new 1\nnew 2\n")
    assert lines(tailer) == ["new 1", "new 2"]
    assert lines(tailer) == []


def test_from_beginning(tmp_path, write):
    log = tmp_path / "app.log"
    write(log, "a\nb\n")
    assert lines(FileTailer(str(log), start_at_end=False)) == ["a", "b"]


def test_partial_lines_are_buffered(tmp_path, write):
    log = tmp_path / "app.log"
    write(log, "")
    tailer = FileTailer(str(log))
    tailer.poll()
    write(log, "hello wo")
    assert lines(tailer) == []
    write(log, "rld\r\nnext")
    assert lines(tailer) == ["hello world"]
    write(log, "\n")
    assert lines(tailer) == ["next"]


def test_rotation_by_rename_reads_rest_of_old_file_then_new_file(tmp_path, write):
    log = tmp_path / "app.log"
    write(log, "")
    tailer = FileTailer(str(log))
    tailer.poll()
    write(log, "before\nlast words")
    os.rename(log, tmp_path / "app.log.1")
    write(log, "fresh 1\nfresh 2\n")
    assert lines(tailer) == ["before", "last words", "fresh 1", "fresh 2"]
    write(log, "fresh 3\n")
    assert lines(tailer) == ["fresh 3"]


def test_rotation_with_delayed_create(tmp_path, write):
    log = tmp_path / "app.log"
    write(log, "")
    tailer = FileTailer(str(log))
    tailer.poll()
    write(log, "one\n")
    os.rename(log, tmp_path / "app.log.1")
    assert lines(tailer) == ["one"]
    assert tailer.paths == []
    write(log, "two\n")
    tailer.refresh()
    assert lines(tailer) == ["two"]


def test_copytruncate(tmp_path, write):
    log = tmp_path / "app.log"
    write(log, "")
    tailer = FileTailer(str(log))
    tailer.poll()
    write(log, "a long line before truncation\n")
    assert lines(tailer) == ["a long line before truncation"]
    write(log, "", mode="w")
    write(log, "short\n")
    assert lines(tailer) == ["short"]


def test_glob_picks_up_new_files_from_their_start(tmp_path, write):
    write(tmp_path / "a.log", "existing\n")
    tailer = FileTailer(str(tmp_path / "*.log"))
    assert tailer.poll() == []
    write(tmp_path / "b.log", "b1\n")
    write(tmp_path / "ignored.txt", "x\n")
    tailer.refresh()
    write(tmp_path / "a.log", "a1\n")
    got = sorted(tailer.poll())
    assert got == [(str(tmp_path / "a.log"), "a1"), (str(tmp_path / "b.log"), "b1")]


def test_missing_file_is_picked_up_when_created(tmp_path, write):
    log = tmp_path / "later.log"
    tailer = FileTailer(str(log))
    assert tailer.poll() == []
    write(log, "hello\n")
    tailer.refresh()
    assert lines(tailer) == ["hello"]


def test_very_long_lines_are_split(tmp_path, write):
    log = tmp_path / "big.log"
    write(log, "")
    tailer = FileTailer(str(log))
    tailer.poll()
    write(log, "x" * (MAX_LINE * 2 + 10) + "\n")
    got = lines(tailer)
    assert [len(x) for x in got] == [MAX_LINE, MAX_LINE, 10]


def test_invalid_utf8_is_replaced(tmp_path):
    log = tmp_path / "bin.log"
    log.write_bytes(b"")
    tailer = FileTailer(str(log))
    tailer.poll()
    with open(log, "ab") as handle:
        handle.write(b"bad \xff byte\n")
    assert lines(tailer) == ["bad � byte"]


def test_stream_reader_reads_until_eof():
    reader = StreamReader(io.StringIO("one\ntwo\r\n"), name="docker").start()
    collected = []
    deadline = time.time() + 5
    while not reader.finished and time.time() < deadline:
        reader.wait(0.1)
        collected.extend(reader.poll())
    assert collected == ["one", "two"]
    assert reader.finished
