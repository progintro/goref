#!/usr/bin/env python3

"""
goref.py: GTP referee to run two Go engines against each other.

Example:
  ./goref.py --black "gnugo --mode gtp" --white "gnugo --mode gtp" --games 10 --main-time 60
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any

GTP_OK = "="
GTP_ERR = "?"

BLACK_SLOT = "black_cmd"
WHITE_SLOT = "white_cmd"

COORD_RE = re.compile(r"^[A-Za-z][0-9]+$")


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


class GTPProtocolError(RuntimeError):
    pass


class GTPClient:
    """
    GTP client without numeric ids (max compatibility).
    Parses responses that start with '=' or '?' and end at a blank line.
    stdout is non-blocking; we drain all available lines per readiness event.
    """

    def __init__(self, cmd: str, label: str, timeout: float = 10.0, verbose: bool = False):
        self.cmd = cmd
        self.label = label
        self.name = label
        self.timeout = float(timeout)
        self.verbose = verbose

        argv = shlex.split(cmd)
        stderr_setting = subprocess.STDOUT if verbose else subprocess.DEVNULL

        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_setting,
            text=True,
            bufsize=1,
        )
        if self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("Failed to open pipes to engine process")

        os.set_blocking(self.proc.stdout.fileno(), False)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.proc.stdout, selectors.EVENT_READ)

    def is_alive(self) -> bool:
        return self.proc.poll() is None

    def send(self, cmd: str) -> Tuple[bool, str]:
        if not self.is_alive():
            raise GTPProtocolError(f"{self.name} is not running")

        if self.verbose:
            eprint(f"[{self.name} >>] {cmd}")

        try:
            self.proc.stdin.write(cmd + "\n")
            self.proc.stdin.flush()
        except BrokenPipeError as ex:
            raise GTPProtocolError(f"{self.name} stdin broken") from ex

        return self._read_response()

    def _read_response(self) -> Tuple[bool, str]:
        deadline = time.time() + self.timeout
        got_header = False
        header_ok: Optional[bool] = None
        payload_lines: List[str] = []

        def handle_line(line: str) -> Optional[Tuple[bool, str]]:
            nonlocal got_header, header_ok, payload_lines

            if self.verbose:
                eprint(f"[{self.name} <<] {line}")

            if not got_header:
                if line == "":
                    return None
                if line.startswith(GTP_OK) or line.startswith(GTP_ERR):
                    got_header = True
                    header_ok = line.startswith(GTP_OK)
                    rest = line[1:].lstrip()
                    if rest:
                        payload_lines.append(rest)
                    return None
                # chatter
                return None

            if line == "":
                return bool(header_ok), "\n".join(payload_lines).strip()

            payload_lines.append(line)
            return None

        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise GTPProtocolError(f"{self.name} timed out waiting for response")

            events = self.sel.select(timeout=min(0.25, remaining))
            if not events:
                continue

            for key, _mask in events:
                if key.fileobj is not self.proc.stdout:
                    continue

                while True:
                    try:
                        raw = self.proc.stdout.readline()
                    except BlockingIOError:
                        break

                    if raw == "":
                        if self.proc.poll() is not None:
                            raise GTPProtocolError(f"{self.name} exited while waiting for response")
                        break

                    done = handle_line(raw.rstrip("\n"))
                    if done is not None:
                        return done

    def safe_name(self):
        try:
            ok, nm = self.send("name")
            if ok and nm.strip():
                self.name = f"{self.label}({nm.strip()})"
            ok, ver = self.send("version")
            if ok and ver.strip():
                self.name = f"{self.name} v{ver.strip()}"
        except Exception:
            pass

    def quit(self):
        if not self.is_alive():
            return
        try:
            self.send("quit")
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=1.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def other_color(c: str) -> str:
    return "W" if c == "B" else "B"


def gtp_col_to_x(col: str) -> int:
    c = col.upper()
    if not ("A" <= c <= "Z"):
        raise ValueError("bad column")
    idx = ord(c) - ord("A")
    if c >= "I":  # GTP skips I
        idx -= 1
    return idx


def parse_gtp_vertex(s: str, size: int) -> Optional[Tuple[int, int]]:
    s = s.strip()
    if s.lower() in ("pass", "resign"):
        return None
    if len(s) < 2:
        raise ValueError("bad vertex")
    col = s[0]
    row = s[1:]
    x = gtp_col_to_x(col)
    if not row.isdigit():
        raise ValueError("bad row")
    y = int(row) - 1
    if x < 0 or x >= size or y < 0 or y >= size:
        raise ValueError("out of bounds")
    return (x, y)


class GoBoard:
    EMPTY = 0
    BLACK = 1
    WHITE = 2

    def __init__(self, size: int):
        self.size = size
        self.grid = [[self.EMPTY for _ in range(size)] for _ in range(size)]
        self.history: List[bytes] = [self._hash_position()]

    def _hash_position(self) -> bytes:
        h = hashlib.blake2b(digest_size=16)
        h.update(bytes([self.size]))
        for y in range(self.size):
            for x in range(self.size):
                h.update(bytes([self.grid[y][x]]))
        return h.digest()

    def at(self, x: int, y: int) -> int:
        return self.grid[y][x]

    def set(self, x: int, y: int, v: int):
        self.grid[y][x] = v

    def neighbors(self, x: int, y: int):
        if x > 0:
            yield (x - 1, y)
        if x + 1 < self.size:
            yield (x + 1, y)
        if y > 0:
            yield (x, y - 1)
        if y + 1 < self.size:
            yield (x, y + 1)

    def group_and_liberties(self, x: int, y: int):
        color = self.at(x, y)
        if color == self.EMPTY:
            return ([], 0)
        stack = [(x, y)]
        seen = {(x, y)}
        group = []
        liberties = set()
        while stack:
            cx, cy = stack.pop()
            group.append((cx, cy))
            for nx, ny in self.neighbors(cx, cy):
                v = self.at(nx, ny)
                if v == self.EMPTY:
                    liberties.add((nx, ny))
                elif v == color and (nx, ny) not in seen:
                    seen.add((nx, ny))
                    stack.append((nx, ny))
        return (group, len(liberties))

    def remove_group(self, stones):
        for x, y in stones:
            self.set(x, y, self.EMPTY)

    def play_move(self, color: str, vertex: Optional[Tuple[int, int]]) -> Tuple[bool, str]:
        c = self.BLACK if color == "B" else self.WHITE
        oc = self.WHITE if c == self.BLACK else self.BLACK

        if vertex is None:
            self.history.append(self._hash_position())
            return True, "pass"

        x, y = vertex
        if self.at(x, y) != self.EMPTY:
            return False, "occupied"

        self.set(x, y, c)

        # captures
        for nx, ny in self.neighbors(x, y):
            if self.at(nx, ny) == oc:
                group, libs = self.group_and_liberties(nx, ny)
                if libs == 0:
                    self.remove_group(group)

        # suicide
        _grp, libs = self.group_and_liberties(x, y)
        if libs == 0:
            return False, "suicide"

        # simple ko
        new_hash = self._hash_position()
        if len(self.history) >= 2 and new_hash == self.history[-2]:
            return False, "ko"

        self.history.append(new_hash)
        return True, "ok"

    def try_play(self, color: str, vertex: Optional[Tuple[int, int]]) -> Tuple[bool, str]:
        snap_grid = [row[:] for row in self.grid]
        snap_hist_len = len(self.history)
        ok, reason = self.play_move(color, vertex)
        if not ok:
            self.grid = [row[:] for row in snap_grid]
            self.history = self.history[:snap_hist_len]
        return ok, reason


@dataclass
class ClockState:
    main_remaining: float
    byo_yomi: float
    byo_stones: int
    byo_remaining: float = 0.0
    stones_remaining: int = 0

    def __post_init__(self):
        if self.byo_yomi > 0 and self.byo_stones > 0:
            self.byo_remaining = self.byo_yomi
            self.stones_remaining = self.byo_stones

    def deduct(self, elapsed: float):
        if self.main_remaining > 0:
            self.main_remaining -= elapsed
            if self.main_remaining > 0:
                return
            spill = -self.main_remaining
            self.main_remaining = 0.0
            if self.byo_yomi <= 0 or self.byo_stones <= 0:
                raise TimeoutError("out of main time (no byo)")
            self.byo_remaining -= spill
        else:
            if self.byo_yomi <= 0 or self.byo_stones <= 0:
                raise TimeoutError("out of time")
            self.byo_remaining -= elapsed

        if self.byo_remaining < 0:
            raise TimeoutError("out of byo-yomi time")

    def finish_move(self):
        if self.main_remaining > 0:
            return
        if self.byo_yomi <= 0 or self.byo_stones <= 0:
            return
        self.stones_remaining -= 1
        if self.stones_remaining <= 0:
            self.stones_remaining = self.byo_stones
            self.byo_remaining = self.byo_yomi

    def gtp_time_left_args(self) -> Tuple[int, int]:
        if self.main_remaining > 0:
            return (max(0, int(self.main_remaining)), 0)
        if self.byo_yomi > 0 and self.byo_stones > 0:
            return (max(0, int(self.byo_remaining)), max(0, int(self.stones_remaining)))
        return (0, 0)


def send_time_settings(e: GTPClient, main_time: int, byo_yomi: int, byo_stones: int):
    e.send(f"time_settings {main_time} {byo_yomi} {byo_stones}")


def send_time_left(e: GTPClient, color: str, clk: ClockState):
    t, s = clk.gtp_time_left_args()
    e.send(f"time_left {color} {t} {s}")


def parse_engine_final_score(s: Optional[str]) -> Optional[Tuple[Optional[str], float, str]]:
    s = (s or "").strip()
    if not s:
        return None
    if s in ("0", "Draw", "DRAW", "Jigo", "JIGO"):
        return (None, 0.0, "0")
    m = re.match(r"^([BW])\+([Rr]|[0-9]+(\.[0-9]+)?)$", s)
    if not m:
        return None
    winner = m.group(1)
    if m.group(2).lower() == "r":
        return (winner, float("inf"), f"{winner}+R")
    margin = float(m.group(2))
    return (winner, margin, f"{winner}+{margin}")


@dataclass
class EngineReport:
    engine: str
    reported_final_score: Optional[str]
    parsed_reported: Optional[str]
    validated_against_judge: bool
    misreported: bool
    misreport_reason: Optional[str]


@dataclass
class JudgeReport:
    judge_cmd: str
    judge_name: str
    judge_final_score: Optional[str]


@dataclass
class GameResult:
    game_index: int
    black_slot: str
    white_slot: str
    engine_black: str
    engine_white: str
    winner_slot: Optional[str]
    winner_color: Optional[str]
    winner_engine: Optional[str]
    reason: str
    moves: int
    komi: float
    judge: JudgeReport
    engine_reports: List[EngineReport]


def slot_for_color(black_slot: str, white_slot: str, color: Optional[str]) -> Optional[str]:
    if color == "B":
        return black_slot
    if color == "W":
        return white_slot
    return None


def setup_one(eng: GTPClient, boardsize: int, komi: float):
    ok, p = eng.send(f"boardsize {boardsize}")
    if not ok:
        raise GTPProtocolError(f"{eng.name} rejected boardsize: {p}")
    ok, p = eng.send(f"komi {komi}")
    if not ok:
        raise GTPProtocolError(f"{eng.name} rejected komi: {p}")
    ok, p = eng.send("clear_board")
    if not ok:
        raise GTPProtocolError(f"{eng.name} rejected clear_board: {p}")


def get_engine_final_score(eng: GTPClient) -> Optional[str]:
    try:
        ok, p = eng.send("final_score")
        if ok and p.strip():
            return p.strip()
    except Exception:
        pass
    return None


def play_match(
    black_cmd: str,
    white_cmd: str,
    judge_cmd: str,
    games: int,
    boardsize: int,
    komi: float,
    max_moves: int,
    gtp_timeout: float,
    swap_colors: bool,
    use_time: bool,
    main_time: int,
    byo_yomi: int,
    byo_stones: int,
    verbose: bool,
) -> List[GameResult]:
    results: List[GameResult] = []

    for gi in range(1, games + 1):
        if swap_colors and (gi % 2 == 0):
            black_slot = WHITE_SLOT
            white_slot = BLACK_SLOT
            b_cmd, w_cmd = white_cmd, black_cmd
            b_label, w_label = "whitecmd:B", "blackcmd:W"
        else:
            black_slot = BLACK_SLOT
            white_slot = WHITE_SLOT
            b_cmd, w_cmd = black_cmd, white_cmd
            b_label, w_label = "blackcmd:B", "whitecmd:W"

        eb = GTPClient(b_cmd, label=b_label, timeout=gtp_timeout, verbose=verbose)
        ew = GTPClient(w_cmd, label=w_label, timeout=gtp_timeout, verbose=verbose)
        judge = GTPClient(judge_cmd, label="judge", timeout=gtp_timeout, verbose=verbose)

        eb.safe_name()
        ew.safe_name()
        judge.safe_name()

        board = GoBoard(boardsize)
        clocks: Dict[str, ClockState] = {
            "B": ClockState(float(main_time), float(byo_yomi), int(byo_stones)),
            "W": ClockState(float(main_time), float(byo_yomi), int(byo_stones)),
        }

        winner_engine: Optional[str] = None
        winner_color: Optional[str] = None
        reason = "unknown"
        move_count = 0
        engine_reports: List[EngineReport] = []
        judge_final: Optional[str] = None

        try:
            # Setup players + judge
            setup_one(eb, boardsize, komi)
            setup_one(ew, boardsize, komi)
            setup_one(judge, boardsize, komi)

            if use_time:
                # best-effort; if engine rejects, we still proceed
                try:
                    send_time_settings(eb, main_time, byo_yomi, byo_stones)
                except Exception:
                    pass
                try:
                    send_time_settings(ew, main_time, byo_yomi, byo_stones)
                except Exception:
                    pass

            consecutive_passes = 0
            to_play = "B"
            engines_by_color: Dict[str, GTPClient] = {"B": eb, "W": ew}

            while True:
                if move_count >= max_moves:
                    reason = f"hit max moves ({max_moves})"
                    break

                current = engines_by_color[to_play]
                oppc = other_color(to_play)
                opponent = engines_by_color[oppc]

                if use_time:
                    # best-effort time_left to both engines
                    try:
                        send_time_left(current, to_play, clocks[to_play])
                    except Exception:
                        pass
                    try:
                        send_time_left(opponent, to_play, clocks[to_play])
                    except Exception:
                        pass

                t0 = time.time()
                try:
                    ok, payload = current.send(f"genmove {to_play}")
                except Exception as ex:
                    ok, payload = False, str(ex)
                elapsed = time.time() - t0

                if use_time:
                    try:
                        clocks[to_play].deduct(elapsed)
                    except TimeoutError:
                        winner_color = oppc
                        winner_engine = opponent.name
                        reason = f"{current.name} lost on time"
                        move_count += 1
                        break

                if not ok:
                    winner_color = oppc
                    winner_engine = opponent.name
                    reason = f"{current.name} genmove failure/timeout: {payload}"
                    move_count += 1
                    break

                raw_move = payload.strip()
                move_lc = raw_move.lower()

                if not raw_move:
                    winner_color = oppc
                    winner_engine = opponent.name
                    reason = f"{current.name} returned empty move"
                    move_count += 1
                    break

                if move_lc == "resign":
                    winner_color = oppc
                    winner_engine = opponent.name
                    reason = f"{current.name} resigned"
                    move_count += 1
                    break

                if move_lc == "pass":
                    vertex = None
                    sync_move = "pass"
                else:
                    if not COORD_RE.match(raw_move):
                        winner_color = oppc
                        winner_engine = opponent.name
                        reason = f"{current.name} invalid move syntax: {raw_move!r}"
                        move_count += 1
                        break
                    try:
                        vertex = parse_gtp_vertex(raw_move, boardsize)
                    except Exception as ex:
                        winner_color = oppc
                        winner_engine = opponent.name
                        reason = f"{current.name} invalid vertex {raw_move!r}: {ex}"
                        move_count += 1
                        break
                    sync_move = raw_move

                ok_leg, why = board.try_play(to_play, vertex)
                if not ok_leg:
                    winner_color = oppc
                    winner_engine = opponent.name
                    reason = f"{current.name} played illegal move {raw_move!r}: {why}"
                    move_count += 1
                    break

                # Sync opponent
                try:
                    ok2, p2 = opponent.send(f"play {to_play} {sync_move}")
                    if not ok2:
                        winner_color = to_play
                        winner_engine = current.name
                        reason = f"{opponent.name} rejected play {to_play} {sync_move}: {p2}"
                        move_count += 1
                        break
                except Exception as ex:
                    winner_color = to_play
                    winner_engine = current.name
                    reason = f"{opponent.name} failed during play-sync: {ex}"
                    move_count += 1
                    break

                # Sync judge (trusted scorer)
                try:
                    okj, pj = judge.send(f"play {to_play} {sync_move}")
                    if not okj:
                        # If judge can't follow the game, abort scoring and forfeit the mover
                        winner_color = oppc
                        winner_engine = opponent.name
                        reason = f"judge rejected play {to_play} {sync_move}: {pj}"
                        move_count += 1
                        break
                except Exception as ex:
                    winner_color = oppc
                    winner_engine = opponent.name
                    reason = f"judge failed during play-sync: {ex}"
                    move_count += 1
                    break

                if use_time:
                    clocks[to_play].finish_move()

                # End condition tracking
                if move_lc == "pass":
                    consecutive_passes += 1
                else:
                    consecutive_passes = 0

                move_count += 1
                if consecutive_passes >= 2:
                    reason = "two consecutive passes"
                    break

                to_play = oppc

            # Official result: judge final_score if game ended normally (two passes)
            if reason == "two consecutive passes":
                judge_final = get_engine_final_score(judge)
                parsed = parse_engine_final_score(judge_final)
                if parsed is None:
                    # scoring failed; declare draw/unknown
                    winner_color = None
                    winner_engine = None
                    reason = f"judge final_score unparseable: {judge_final!r}"
                else:
                    jc, _jm, _jnorm = parsed
                    winner_color = jc
                    if winner_color == "B":
                        winner_engine = eb.name
                    elif winner_color == "W":
                        winner_engine = ew.name
                    else:
                        winner_engine = None  # draw

            # Validate engines vs judge (misreport means disagree with judge)
            for eng in (eb, ew):
                rep = get_engine_final_score(eng)
                parsed = parse_engine_final_score(rep)
                if judge_final is None:
                    engine_reports.append(
                        EngineReport(
                            engine=eng.name,
                            reported_final_score=rep,
                            parsed_reported=parsed[2] if parsed else None,
                            validated_against_judge=False,
                            misreported=False,
                            misreport_reason=None,
                        )
                    )
                else:
                    if rep is None:
                        engine_reports.append(
                            EngineReport(
                                engine=eng.name,
                                reported_final_score=None,
                                parsed_reported=None,
                                validated_against_judge=True,
                                misreported=True,
                                misreport_reason="engine did not provide final_score",
                            )
                        )
                    else:
                        # Normalize comparison using parsed normalization when possible
                        jparsed = parse_engine_final_score(judge_final)
                        if jparsed is None or parsed is None:
                            mis = (rep.strip() != (judge_final or "").strip())
                            why = None if not mis else f"engine final_score {rep!r} != judge {judge_final!r}"
                            engine_reports.append(
                                EngineReport(
                                    engine=eng.name,
                                    reported_final_score=rep,
                                    parsed_reported=parsed[2] if parsed else None,
                                    validated_against_judge=True,
                                    misreported=mis,
                                    misreport_reason=why,
                                )
                            )
                        else:
                            mis = (parsed[2] != jparsed[2])
                            why = None if not mis else f"engine {parsed[2]} != judge {jparsed[2]}"
                            engine_reports.append(
                                EngineReport(
                                    engine=eng.name,
                                    reported_final_score=rep,
                                    parsed_reported=parsed[2],
                                    validated_against_judge=True,
                                    misreported=mis,
                                    misreport_reason=why,
                                )
                            )

            winner_slot = slot_for_color(black_slot, white_slot, winner_color)

            results.append(
                GameResult(
                    game_index=gi,
                    black_slot=black_slot,
                    white_slot=white_slot,
                    engine_black=eb.name,
                    engine_white=ew.name,
                    winner_slot=winner_slot,
                    winner_color=winner_color,
                    winner_engine=winner_engine,
                    reason=reason,
                    moves=move_count,
                    komi=komi,
                    judge=JudgeReport(judge_cmd=judge_cmd, judge_name=judge.name, judge_final_score=judge_final),
                    engine_reports=engine_reports,
                )
            )

        except Exception as ex:
            # Any setup crash etc: forfeit the side we can't reliably determine -> mark as judge/driver failure
            results.append(
                GameResult(
                    game_index=gi,
                    black_slot=black_slot,
                    white_slot=white_slot,
                    engine_black=eb.name,
                    engine_white=ew.name,
                    winner_slot=None,
                    winner_color=None,
                    winner_engine=None,
                    reason=f"referee error: {ex}",
                    moves=move_count,
                    komi=komi,
                    judge=JudgeReport(judge_cmd=judge_cmd, judge_name=judge.name, judge_final_score=judge_final),
                    engine_reports=engine_reports,
                )
            )
        finally:
            eb.quit()
            ew.quit()
            judge.quit()

    return results


def summarize_json(results: List[GameResult], black_cmd: str, white_cmd: str) -> str:
    slot_wins = {BLACK_SLOT: 0, WHITE_SLOT: 0}
    draws = 0
    misreports = 0
    for r in results:
        if r.winner_slot is None:
            draws += 1
        else:
            slot_wins[r.winner_slot] += 1
        misreports += sum(1 for er in r.engine_reports if er.misreported)

    payload: Dict[str, Any] = {
        "games": len(results),
        "commands": {BLACK_SLOT: black_cmd, WHITE_SLOT: white_cmd},
        "overall_by_slot": {BLACK_SLOT: slot_wins[BLACK_SLOT], WHITE_SLOT: slot_wins[WHITE_SLOT], "draws": draws},
        "engine_misreports_detected": misreports,
        "results": [asdict(r) for r in results],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def summarize_text(results: List[GameResult], black_cmd: str, white_cmd: str) -> str:
    slot_wins = {BLACK_SLOT: 0, WHITE_SLOT: 0}
    draws = 0
    misreports = 0
    for r in results:
        if r.winner_slot is None:
            draws += 1
        else:
            slot_wins[r.winner_slot] += 1
        misreports += sum(1 for er in r.engine_reports if er.misreported)

    lines: List[str] = []
    lines.append(f"Games: {len(results)}")
    lines.append("Overall (by command slot):")
    lines.append(f"  {BLACK_SLOT}: {slot_wins[BLACK_SLOT]}")
    lines.append(f"  {WHITE_SLOT}: {slot_wins[WHITE_SLOT]}")
    lines.append(f"  draws: {draws}")
    lines.append(f"Engine misreports detected (vs judge): {misreports}")
    lines.append("")
    lines.append("Commands:")
    lines.append(f"  {BLACK_SLOT} = {black_cmd}")
    lines.append(f"  {WHITE_SLOT} = {white_cmd}")
    lines.append("")
    for r in results:
        winner = "Draw/Unknown" if r.winner_slot is None else f"{r.winner_slot} ({r.winner_color})"
        j = r.judge.judge_final_score or "-"
        lines.append(
            f"Game {r.game_index}: Winner={winner} Judge={j} Moves={r.moves} End={r.reason}"
        )
        for er in r.engine_reports:
            if er.validated_against_judge:
                flag = "MISREPORT" if er.misreported else "ok"
                lines.append(f"  final_score {er.engine}: {er.reported_final_score} [{flag}]")
            else:
                lines.append(f"  final_score {er.engine}: {er.reported_final_score} [not validated]")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="GTP referee for two engines with trusted GNU Go judge scoring.")
    ap.add_argument("--black", required=True, help='Command for BLACK slot engine, e.g. "gnugo --mode gtp"')
    ap.add_argument("--white", required=True, help='Command for WHITE slot engine, e.g. "gnugo --mode gtp"')

    # Trusted judge defaults to GNU Go Chinese rules + capture dead stones.
    ap.add_argument(
        "--judge",
        default="gnugo --mode gtp --chinese-rules --capture-all-dead",
        help='Trusted judge command (default: "gnugo --mode gtp --chinese-rules --capture-all-dead")',
    )

    ap.add_argument("--games", type=int, default=1)
    ap.add_argument("--swap-colors", action="store_true")
    ap.add_argument("--boardsize", type=int, default=19)

    # Standard komi for Chinese rules
    ap.add_argument("--komi", type=float, default=7.5)

    ap.add_argument("--max-moves", type=int, default=2000)
    ap.add_argument("--gtp-timeout", type=float, default=10.0)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--format", choices=["text", "json"], default="text")

    ap.add_argument("--main-time", type=int, default=0)
    ap.add_argument("--byo-yomi", type=int, default=0)
    ap.add_argument("--byo-stones", type=int, default=0)

    args = ap.parse_args()

    use_time = args.main_time > 0 or (args.byo_yomi > 0 and args.byo_stones > 0)
    if (args.byo_yomi > 0) != (args.byo_stones > 0):
        ap.error("--byo-yomi and --byo-stones must be set together (both > 0)")

    results = play_match(
        black_cmd=args.black,
        white_cmd=args.white,
        judge_cmd=args.judge,
        games=args.games,
        boardsize=args.boardsize,
        komi=args.komi,
        max_moves=args.max_moves,
        gtp_timeout=args.gtp_timeout,
        swap_colors=args.swap_colors,
        use_time=use_time,
        main_time=args.main_time,
        byo_yomi=args.byo_yomi,
        byo_stones=args.byo_stones,
        verbose=args.verbose,
    )

    if args.format == "json":
        print(summarize_json(results, args.black, args.white))
    else:
        print(summarize_text(results, args.black, args.white))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

