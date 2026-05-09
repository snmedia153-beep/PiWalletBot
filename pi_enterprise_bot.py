import os
import json
import threading
import time
import hmac
import hashlib
import unicodedata
import struct
from decimal import Decimal, ROUND_DOWN
from datetime import datetime
import customtkinter as ctk
from tkinter import messagebox

from stellar_sdk import Server, Keypair, Network, TransactionBuilder, Asset


# ==============================
# 기본 설정
# ==============================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

PI_HORIZON_URL = "https://api.mainnet.minepi.com"
PI_NETWORK_PASSPHRASE = "Pi Network"

# Pi/Stellar 계열 수수료 단위:
# 1 PI = 10,000,000 stroops
# 100,000 stroops = 0.01 PI
#
# 기존 10,000 stroops는 Pi Horizon에서 tx_insufficient_fee가 발생할 수 있습니다.
# fee_stats 조회에 실패하면 0.01 PI를 기본 max fee bid로 사용합니다.
DEFAULT_BASE_FEE_STROOPS = 1000000
MIN_BASE_FEE_STROOPS = 1000000
MAX_BASE_FEE_STROOPS = 5000000

PI_SAFE_RESERVE = Decimal("0.05")

PRESET_FILE = "pi_wallets.json"

# 송금 후 Horizon 반영 확인 설정
TX_CONFIRM_TIMEOUT_SEC = 45
TX_CONFIRM_POLL_INTERVAL_SEC = 3


# ==============================
# 24단어 파생 유틸 - bip-utils 불필요
# ==============================
def normalize_mnemonic(text: str) -> str:
    return " ".join(text.strip().lower().split())


def mnemonic_to_seed_bip39(mnemonic: str, passphrase: str = "") -> bytes:
    """
    BIP39 seed 생성.
    외부 라이브러리 없이 hashlib.pbkdf2_hmac 사용.
    """
    mnemonic = unicodedata.normalize("NFKD", normalize_mnemonic(mnemonic))
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        salt.encode("utf-8"),
        2048,
        dklen=64,
    )


def slip10_ed25519_master_key(seed: bytes):
    """
    SLIP-0010 ed25519 master key.
    반환: (private_key_seed_32_bytes, chain_code_32_bytes)
    """
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def slip10_ed25519_ckd_priv(parent_key: bytes, parent_chain_code: bytes, index: int):
    """
    SLIP-0010 ed25519 hardened child derivation.
    ed25519는 hardened derivation만 지원.
    """
    if index < 0x80000000:
        index += 0x80000000

    data = b"\x00" + parent_key + struct.pack(">L", index)
    digest = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def parse_hardened_path(path: str):
    """
    예: m/44'/314159'/0'
    ed25519용으로 모든 index를 hardened로 처리.
    """
    path = path.strip()
    if path in ("m", "M", ""):
        return []

    if not path.startswith("m/"):
        raise ValueError(f"잘못된 파생 경로입니다: {path}")

    result = []
    for item in path[2:].split("/"):
        hardened = item.endswith("'") or item.endswith("h") or item.endswith("H")
        number_part = item[:-1] if hardened else item

        if not number_part.isdigit():
            raise ValueError(f"잘못된 파생 경로 index입니다: {item}")

        index = int(number_part)
        if index < 0 or index >= 0x80000000:
            raise ValueError(f"파생 경로 index 범위를 벗어났습니다: {item}")

        # ed25519는 일반 child derivation을 지원하지 않으므로 전부 hardened 처리
        result.append(index + 0x80000000)

    return result


def derive_ed25519_seed_from_mnemonic_path(mnemonic: str, path: str, bip39_passphrase: str = "") -> bytes:
    """
    BIP39 mnemonic -> SLIP-0010 ed25519 private seed 32 bytes.
    이 32바이트 seed를 Stellar Keypair.from_raw_ed25519_seed에 넣는다.
    """
    seed = mnemonic_to_seed_bip39(mnemonic, bip39_passphrase)
    key, chain_code = slip10_ed25519_master_key(seed)

    for index in parse_hardened_path(path):
        key, chain_code = slip10_ed25519_ckd_priv(key, chain_code, index)

    return key


def quantize_pi(amount: Decimal) -> str:
    q = amount.quantize(Decimal("0.0000001"), rounding=ROUND_DOWN)
    return format(q, "f")


def short_key(key: str) -> str:
    if not key:
        return "-"
    if len(key) <= 18:
        return key
    return f"{key[:10]}...{key[-8:]}"


def stroops_to_pi(stroops: int) -> Decimal:
    return (Decimal(int(stroops)) / Decimal("10000000")).quantize(
        Decimal("0.0000001"),
        rounding=ROUND_DOWN,
    )


def build_pi_derivation_candidates(max_account_index: int = 30):
    """
    Pi Wallet 공개 예제는 m/44'/314159'/0'를 사용하지만,
    사용자가 여러 지갑을 만들었거나 구현체 차이가 있을 수 있어
    계정 index 후보를 넓게 스캔합니다.

    반환 항목:
        (bip39_passphrase, path)
    """
    # 일반적으로는 빈 passphrase입니다.
    # 아래 비어 있지 않은 후보는 실제 Pi 공식값이라고 단정하지 않고,
    # 사용자가 이전에 별도 passphrase를 썼거나 구현체 차이가 있을 때만 탐색용으로 둡니다.
    bip39_passphrases = [""]

    candidates = []

    # Pi coin_type 우선
    for i in range(max_account_index + 1):
        candidates.append(("", f"m/44'/314159'/{i}'"))

    # 일부 구현체가 추가 depth를 쓰는 경우 대비
    for i in range(max_account_index + 1):
        candidates.append(("", f"m/44'/314159'/0'/{i}'"))

    for i in range(max_account_index + 1):
        candidates.append(("", f"m/44'/314159'/0'/0'/{i}'"))

    # Stellar 표준 후보도 보조 확인
    for i in range(10):
        candidates.append(("", f"m/44'/148'/{i}'"))

    # 중복 제거
    seen = set()
    unique = []
    for item in candidates:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


class PiEnterpriseBot(ctk.CTk):
    """
    Pi Network Auto Transfer - No bip-utils Edition

    핵심:
    - bip-utils 완전 제거
    - Python 표준 라이브러리 hashlib/hmac/struct로 BIP39 seed + SLIP10 ed25519 파생
    - 24단어 + 내 지갑주소만으로 자동 경로 매칭
    """

    # 고정 3개만 보지 않고, build_pi_derivation_candidates()로 넓게 스캔합니다.
    DERIVATION_PATH_CANDIDATES = []

    def __init__(self):
        super().__init__()

        self.title("Pi Network Auto Transfer - No bip-utils Edition")
        self.geometry("1080x900")
        self.minsize(980, 850)

        self.is_running = False
        self.server = Server(PI_HORIZON_URL)

        self.presets = self.load_presets()
        self.run_config = {}
        self.active_keypair = None
        self.active_derivation_path = None

        self.setup_ui()
        self.refresh_preset_combo()

    # ==============================
    # 프리셋
    # ==============================
    def load_presets(self):
        if os.path.exists(PRESET_FILE):
            try:
                with open(PRESET_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        return {}

    def save_presets_to_file(self):
        with open(PRESET_FILE, "w", encoding="utf-8") as f:
            json.dump(self.presets, f, ensure_ascii=False, indent=4)

    # ==============================
    # UI
    # ==============================
    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        left_frame = ctk.CTkFrame(self, width=310, corner_radius=0)
        left_frame.grid(row=0, column=0, sticky="nsew")
        left_frame.grid_propagate(False)

        ctk.CTkLabel(
            left_frame,
            text="Pi 지갑 자동 이체",
            font=("Malgun Gothic", 22, "bold"),
        ).pack(pady=(28, 6), padx=20)

        ctk.CTkLabel(
            left_frame,
            text="24단어 + 내 지갑주소 기반",
            font=("Malgun Gothic", 13),
            text_color="#93C5FD",
        ).pack(pady=(0, 18), padx=20)

        self.combo_presets = ctk.CTkComboBox(
            left_frame,
            values=[],
            font=("Malgun Gothic", 14),
            command=self.on_preset_selected,
        )
        self.combo_presets.pack(pady=8, padx=20, fill="x")

        ctk.CTkButton(
            left_frame,
            text="💾 프로필 저장",
            font=("Malgun Gothic", 13),
            command=self.save_new_preset,
        ).pack(pady=5, padx=20, fill="x")

        ctk.CTkButton(
            left_frame,
            text="✏️ 선택 프로필 수정",
            font=("Malgun Gothic", 13),
            fg_color="#F59E0B",
            hover_color="#D97706",
            command=self.edit_preset,
        ).pack(pady=5, padx=20, fill="x")

        ctk.CTkButton(
            left_frame,
            text="🗑️ 선택 프로필 삭제",
            font=("Malgun Gothic", 13),
            fg_color="#EF4444",
            hover_color="#B91C1C",
            command=self.delete_preset,
        ).pack(pady=5, padx=20, fill="x")

        separator = ctk.CTkFrame(left_frame, height=2, fg_color="#334155")
        separator.pack(fill="x", padx=20, pady=(20, 14))

        self.btn_verify = ctk.CTkButton(
            left_frame,
            text="🔍 24단어/주소 검사",
            font=("Malgun Gothic", 14, "bold"),
            height=42,
            fg_color="#3B82F6",
            hover_color="#2563EB",
            command=self.verify_seed,
        )
        self.btn_verify.pack(fill="x", pady=(0, 12), padx=20)

        self.btn_start = ctk.CTkButton(
            left_frame,
            text="▶ 자동 감시 시작",
            font=("Malgun Gothic", 15, "bold"),
            height=46,
            fg_color="#10B981",
            hover_color="#059669",
            command=self.start_bot,
        )
        self.btn_start.pack(fill="x", pady=5, padx=20)

        self.btn_stop = ctk.CTkButton(
            left_frame,
            text="■ 감시 중지",
            font=("Malgun Gothic", 15, "bold"),
            height=46,
            fg_color="#EF4444",
            hover_color="#B91C1C",
            state="disabled",
            command=self.stop_bot,
        )
        self.btn_stop.pack(fill="x", pady=5, padx=20)

        self.dash_frame = ctk.CTkFrame(left_frame, corner_radius=12, fg_color="#1E293B")
        ctk.CTkLabel(
            self.dash_frame,
            text="📊 실시간 상태",
            font=("Malgun Gothic", 15, "bold"),
            text_color="#60A5FA",
        ).pack(pady=(15, 5))

        self.lbl_balance = ctk.CTkLabel(
            self.dash_frame,
            text="조회 대기중...",
            font=("Consolas", 20, "bold"),
            text_color="#A7F3D0",
        )
        self.lbl_balance.pack(pady=(0, 12))

        ctk.CTkLabel(
            self.dash_frame,
            text="[최근 거래 내역 5건]",
            font=("Malgun Gothic", 12, "bold"),
        ).pack()

        self.tx_labels = []
        for _ in range(5):
            lbl = ctk.CTkLabel(self.dash_frame, text="-", font=("Consolas", 11))
            lbl.pack(pady=2)
            self.tx_labels.append(lbl)

        self.lbl_active_path = ctk.CTkLabel(
            self.dash_frame,
            text="Path: -",
            font=("Consolas", 10),
            text_color="#CBD5E1",
        )
        self.lbl_active_path.pack(pady=(10, 14))

        right_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=24, pady=24)

        info_frame = ctk.CTkFrame(right_frame, corner_radius=12)
        info_frame.pack(fill="x", pady=(0, 14), ipady=8)

        ctk.CTkLabel(
            info_frame,
            text="🔐 내 지갑 정보",
            font=("Malgun Gothic", 17, "bold"),
            text_color="#60A5FA",
        ).pack(anchor="w", padx=20, pady=(15, 10))

        ctk.CTkLabel(info_frame, text="내 Pi 지갑 주소", font=("Malgun Gothic", 13)).pack(anchor="w", padx=20)
        self.entry_pub = ctk.CTkEntry(info_frame, font=("Consolas", 13), height=36)
        self.entry_pub.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(info_frame, text="내 Pi 지갑 24개 영단어 구절", font=("Malgun Gothic", 13)).pack(anchor="w", padx=20)
        self.entry_sec = ctk.CTkEntry(info_frame, show="*", font=("Consolas", 13), height=36)
        self.entry_sec.pack(fill="x", padx=20, pady=(0, 8))

        helper_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        helper_frame.pack(fill="x", padx=20, pady=(0, 8))

        self.show_secret_var = ctk.IntVar(value=0)
        ctk.CTkCheckBox(
            helper_frame,
            text="24단어 보기",
            variable=self.show_secret_var,
            command=self.toggle_secret_visibility,
            font=("Malgun Gothic", 12),
        ).pack(side="left")

        self.save_secret_var = ctk.IntVar(value=0)
        ctk.CTkCheckBox(
            helper_frame,
            text="프로필에 24단어 저장",
            variable=self.save_secret_var,
            font=("Malgun Gothic", 12),
            text_color="#FCA5A5",
        ).pack(side="left", padx=(18, 0))

        ctk.CTkLabel(info_frame, text="입금 받을 목적지 Pi 지갑 주소", font=("Malgun Gothic", 13)).pack(anchor="w", padx=20)
        self.entry_target = ctk.CTkEntry(info_frame, font=("Consolas", 13), height=36)
        self.entry_target.pack(fill="x", padx=20, pady=(0, 12))

        opt_frame = ctk.CTkFrame(right_frame, corner_radius=12)
        opt_frame.pack(fill="x", pady=10, ipady=10)

        ctk.CTkLabel(
            opt_frame,
            text="⚙️ 자동 감시 및 이체 설정",
            font=("Malgun Gothic", 17, "bold"),
            text_color="#60A5FA",
        ).pack(anchor="w", padx=20, pady=(15, 10))

        row1 = ctk.CTkFrame(opt_frame, fg_color="transparent")
        row1.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(row1, text="조건: 내 잔고가 다음 PI 이상일 때", font=("Malgun Gothic", 14)).pack(side="left")
        self.entry_min_pi = ctk.CTkEntry(row1, width=110, font=("Consolas", 14))
        self.entry_min_pi.pack(side="left", padx=10)
        self.entry_min_pi.insert(0, "10.0")

        row2 = ctk.CTkFrame(opt_frame, fg_color="transparent")
        row2.pack(fill="x", padx=20, pady=5)
        ctk.CTkLabel(row2, text="주기: 잔고 조회 간격", font=("Malgun Gothic", 14)).pack(side="left")
        self.entry_interval = ctk.CTkEntry(row2, width=110, font=("Consolas", 14))
        self.entry_interval.pack(side="left", padx=10)
        self.entry_interval.insert(0, "5")
        ctk.CTkLabel(row2, text="초", font=("Malgun Gothic", 14)).pack(side="left")

        self.transfer_mode = ctk.IntVar(value=1)
        ctk.CTkRadioButton(
            opt_frame,
            text=f"전액 이동: 안전 여유분 {PI_SAFE_RESERVE} PI 제외 후 전송",
            variable=self.transfer_mode,
            value=1,
            font=("Malgun Gothic", 14),
        ).pack(anchor="w", padx=20, pady=10)

        row3 = ctk.CTkFrame(opt_frame, fg_color="transparent")
        row3.pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkRadioButton(
            row3,
            text="고정 수량 이동",
            variable=self.transfer_mode,
            value=2,
            font=("Malgun Gothic", 14),
        ).pack(side="left")

        self.entry_fixed = ctk.CTkEntry(row3, width=110, font=("Consolas", 14))
        self.entry_fixed.pack(side="left", padx=10)
        self.entry_fixed.insert(0, "5.0")
        ctk.CTkLabel(row3, text="PI", font=("Malgun Gothic", 14)).pack(side="left")

        warning_frame = ctk.CTkFrame(right_frame, corner_radius=12, fg_color="#3B1F1F")
        warning_frame.pack(fill="x", pady=(6, 12), ipady=8)
        ctk.CTkLabel(
            warning_frame,
            text=(
                "주의: 24단어는 지갑 전체 권한입니다. 기본값은 프로필에 저장하지 않습니다. "
                "공용 PC에서는 절대 사용하지 마세요."
            ),
            font=("Malgun Gothic", 12),
            text_color="#FCA5A5",
            wraplength=660,
            justify="left",
        ).pack(anchor="w", padx=16, pady=8)

        ctk.CTkLabel(right_frame, text="시스템 로그", font=("Malgun Gothic", 14, "bold")).pack(anchor="w", pady=(4, 5))
        self.log_area = ctk.CTkTextbox(right_frame, font=("Consolas", 13), fg_color="#0F172A", text_color="#34D399")
        self.log_area.pack(fill="both", expand=True)
        self.log_area.configure(state="disabled")

    def toggle_secret_visibility(self):
        self.entry_sec.configure(show="" if self.show_secret_var.get() else "*")

    # ==============================
    # 핵심: 24단어 -> Pi Keypair
    # ==============================
    def validate_public_key(self, pub_key: str, label: str = "지갑 주소"):
        try:
            Keypair.from_public_key(pub_key)
        except Exception:
            raise ValueError(f"{label} 형식이 올바르지 않습니다.")

    def derive_keypair_from_mnemonic_path(self, mnemonic: str, path: str, bip39_passphrase: str = "") -> Keypair:
        mnemonic = normalize_mnemonic(mnemonic)

        words = mnemonic.split()
        if len(words) != 24:
            raise ValueError("24개 영단어를 정확히 입력하세요.")

        raw_private_seed = derive_ed25519_seed_from_mnemonic_path(mnemonic, path, bip39_passphrase)
        return Keypair.from_raw_ed25519_seed(raw_private_seed)

    def get_keypair_from_input(self, secret_input: str, expected_public_key: str = ""):
        """
        반환값:
            (keypair, method, derivation_path)

        expected_public_key가 있으면 후보 경로 중 해당 주소와 일치하는 키페어를 자동 선택합니다.
        """
        secret_input = secret_input.strip()
        expected_public_key = expected_public_key.strip()

        if not secret_input:
            raise ValueError("24단어 구절을 입력하세요.")

        words = secret_input.split()

        # S... 시크릿 키도 보조적으로 지원
        if secret_input.startswith("S") and len(secret_input) == 56:
            kp = Keypair.from_secret(secret_input)
            if expected_public_key and kp.public_key != expected_public_key:
                raise ValueError(
                    "입력한 시크릿 키에서 생성된 주소가 내 지갑 주소와 다릅니다.\n"
                    f"생성 주소: {kp.public_key}"
                )
            return kp, "secret", "S..."

        if len(words) != 24:
            raise ValueError("Pi 지갑 24개 영단어를 정확히 입력하세요.")

        mnemonic = normalize_mnemonic(secret_input)

        mismatch_results = []
        candidates = build_pi_derivation_candidates(max_account_index=30)

        for bip39_passphrase, path in candidates:
            kp = self.derive_keypair_from_mnemonic_path(mnemonic, path, bip39_passphrase)
            path_label = path if not bip39_passphrase else f"{path} / passphrase={bip39_passphrase!r}"

            if expected_public_key and kp.public_key == expected_public_key:
                return kp, "mnemonic", path_label

            mismatch_results.append((path_label, kp.public_key))

        if expected_public_key:
            # 너무 길어지는 것을 방지하면서도 진단 가능하게 앞쪽 후보를 보여줍니다.
            preview = "\n".join([f"{p} -> {short_key(k)}" for p, k in mismatch_results[:18]])
            first_pub = mismatch_results[0][1] if mismatch_results else "-"
            raise ValueError(
                "24단어에서 여러 Pi/Stellar 후보 주소를 만들었지만 입력한 내 지갑 주소와 일치하지 않았습니다.\n\n"
                f"입력 주소: {expected_public_key}\n"
                f"Pi 기본 경로 생성 주소: {first_pub}\n\n"
                f"확인한 후보 일부:\n{preview}\n\n"
                "가장 흔한 원인:\n"
                "1) Pi Browser에서 이 24단어로 로그인한 뒤 표시되는 지갑 주소와, 프로그램에 입력한 주소가 다름\n"
                "2) 현재 Pi 앱 Mainnet Checklist에 확정된 주소와 Pi Browser 지갑 주소를 혼동함\n"
                "3) 24단어 중 하나가 비슷한 단어로 잘못 복사됨\n\n"
                "Pi Browser > Wallet에서 같은 24단어로 직접 로그인한 뒤 화면에 표시되는 지갑 주소를 다시 복사해 넣어주세요."
            )

        # expected_public_key가 없으면 Pi 기본 경로 0번을 반환
        default_passphrase, default_path = candidates[0]
        kp = self.derive_keypair_from_mnemonic_path(mnemonic, default_path, default_passphrase)
        return kp, "mnemonic", default_path

    # ==============================
    # 검증
    # ==============================
    def verify_seed(self):
        pub_key = self.entry_pub.get().strip()
        sec_key = self.entry_sec.get().strip()

        if not pub_key:
            messagebox.showwarning("입력 필요", "내 Pi 지갑 주소를 입력해주세요.")
            return

        if not sec_key:
            messagebox.showwarning("입력 필요", "24개 영단어 구절을 입력해주세요.")
            return

        try:
            self.validate_public_key(pub_key, "내 Pi 지갑 주소")
            kp, method, path = self.get_keypair_from_input(sec_key, pub_key)

            msg = (
                "✅ 지갑 검증 성공\n\n"
                "24단어에서 생성된 주소가 입력한 Pi 지갑 주소와 일치합니다.\n\n"
                f"내 주소: {short_key(pub_key)}\n"
                f"파생 주소: {short_key(kp.public_key)}\n"
                f"사용 경로: {path}\n\n"
                "이 상태에서는 송금 서명도 같은 지갑 기준으로 처리됩니다."
            )
            self.show_result_popup("지갑 검증 성공", msg, "#34D399")

        except Exception as e:
            self.show_result_popup("지갑 검증 실패", f"❌ 검증 실패\n\n{str(e)}", "#F87171")

    def show_result_popup(self, title: str, msg: str, color: str):
        popup = ctk.CTkToplevel(self)
        popup.title(title)
        popup.geometry("620x420")
        popup.grab_set()

        lbl_result = ctk.CTkLabel(
            popup,
            text=msg,
            font=("Malgun Gothic", 14),
            text_color=color,
            justify="left",
            wraplength=560,
        )
        lbl_result.pack(expand=True, padx=24, pady=(24, 12))

        ctk.CTkButton(popup, text="확인", width=140, command=popup.destroy).pack(pady=(0, 22))

    # ==============================
    # 프리셋 관리
    # ==============================
    def refresh_preset_combo(self):
        aliases = list(self.presets.keys())
        if aliases:
            self.combo_presets.configure(values=aliases)
            current = aliases[0]
            self.combo_presets.set(current)
            self.on_preset_selected(current)
        else:
            self.combo_presets.configure(values=["저장된 프로필 없음"])
            self.combo_presets.set("저장된 프로필 없음")

    def on_preset_selected(self, choice):
        if choice not in self.presets:
            return

        data = self.presets[choice]
        self.entry_pub.delete(0, "end")
        self.entry_pub.insert(0, data.get("pub", ""))

        self.entry_sec.delete(0, "end")
        self.entry_sec.insert(0, data.get("sec", ""))

        self.entry_target.delete(0, "end")
        self.entry_target.insert(0, data.get("target", ""))

    def save_new_preset(self):
        dialog = ctk.CTkInputDialog(text="저장할 프로필 별칭:\n예: 내 메인지갑", title="새 프로필 저장")
        alias = dialog.get_input()
        if not alias:
            return

        sec_to_save = ""
        if self.save_secret_var.get():
            if messagebox.askyesno(
                "보안 경고",
                "24단어를 pi_wallets.json 파일에 저장합니다.\n"
                "이 파일이 유출되면 지갑 자산이 위험합니다.\n\n"
                "정말 저장하시겠습니까?",
            ):
                sec_to_save = self.entry_sec.get().strip()

        self.presets[alias] = {
            "pub": self.entry_pub.get().strip(),
            "sec": sec_to_save,
            "target": self.entry_target.get().strip(),
        }

        self.save_presets_to_file()
        self.refresh_preset_combo()
        self.combo_presets.set(alias)
        messagebox.showinfo("성공", f"[{alias}] 프로필이 저장되었습니다.")

    def delete_preset(self):
        alias = self.combo_presets.get()
        if alias in self.presets:
            if messagebox.askyesno("삭제 확인", f"[{alias}] 프로필을 삭제하시겠습니까?"):
                del self.presets[alias]
                self.save_presets_to_file()
                self.refresh_preset_combo()
                self.entry_pub.delete(0, "end")
                self.entry_sec.delete(0, "end")
                self.entry_target.delete(0, "end")

    def edit_preset(self):
        alias = self.combo_presets.get()
        if alias not in self.presets:
            messagebox.showwarning("오류", "수정할 프로필을 먼저 선택하세요.")
            return

        popup = ctk.CTkToplevel(self)
        popup.title(f"프로필 수정: {alias}")
        popup.geometry("560x430")
        popup.grab_set()

        ctk.CTkLabel(popup, text="내 Pi 지갑 주소:").pack(pady=(14, 0))
        e_pub = ctk.CTkEntry(popup, width=500)
        e_pub.pack()
        e_pub.insert(0, self.presets[alias].get("pub", ""))

        ctk.CTkLabel(popup, text="24단어 구절: 기본은 저장하지 않는 것을 권장").pack(pady=(12, 0))
        e_sec = ctk.CTkEntry(popup, width=500, show="*")
        e_sec.pack()
        e_sec.insert(0, self.presets[alias].get("sec", ""))

        save_secret_edit_var = ctk.IntVar(value=1 if self.presets[alias].get("sec", "") else 0)
        ctk.CTkCheckBox(
            popup,
            text="이 프로필에 24단어 저장",
            variable=save_secret_edit_var,
            text_color="#FCA5A5",
        ).pack(pady=(8, 0))

        ctk.CTkLabel(popup, text="입금 목적지 주소:").pack(pady=(12, 0))
        e_target = ctk.CTkEntry(popup, width=500)
        e_target.pack()
        e_target.insert(0, self.presets[alias].get("target", ""))

        def save_changes():
            sec_value = ""
            if save_secret_edit_var.get():
                if messagebox.askyesno(
                    "보안 경고",
                    "24단어를 pi_wallets.json 파일에 저장합니다.\n"
                    "정말 저장하시겠습니까?",
                ):
                    sec_value = e_sec.get().strip()

            self.presets[alias] = {
                "pub": e_pub.get().strip(),
                "sec": sec_value,
                "target": e_target.get().strip(),
            }
            self.save_presets_to_file()
            self.on_preset_selected(alias)
            popup.destroy()
            messagebox.showinfo("완료", "수정되었습니다.")

        ctk.CTkButton(popup, text="저장하기", command=save_changes).pack(pady=24)

    # ==============================
    # 로그 / 대시보드
    # ==============================
    def log(self, message):
        self.after(0, self._append_log, message)

    def _append_log(self, message):
        self.log_area.configure(state="normal")
        time_str = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert("end", f"[{time_str}] {message}\n")

        lines = int(self.log_area.index("end-1c").split(".")[0])
        if lines > 600:
            self.log_area.delete("1.0", f"{lines - 600 + 1}.0")

        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def toggle_ui(self, is_running):
        state = "disabled" if is_running else "normal"

        for widget in [
            self.entry_pub,
            self.entry_sec,
            self.entry_target,
            self.entry_min_pi,
            self.entry_interval,
            self.entry_fixed,
            self.combo_presets,
        ]:
            widget.configure(state=state)

        if is_running:
            self.btn_verify.configure(state="disabled", fg_color="gray")
            self.btn_start.configure(state="disabled", fg_color="gray")
            self.btn_stop.configure(state="normal", fg_color="#EF4444")
            self.dash_frame.pack(fill="x", padx=15, pady=(16, 20))
        else:
            self.btn_verify.configure(state="normal", fg_color="#3B82F6")
            self.btn_start.configure(state="normal", fg_color="#10B981")
            self.btn_stop.configure(state="disabled", fg_color="gray")
            self.dash_frame.pack_forget()

    def update_dashboard(self, balance: Decimal, txs):
        self.lbl_balance.configure(text=f"{quantize_pi(balance)} PI")
        self.lbl_active_path.configure(text=f"Path: {self.active_derivation_path or '-'}")

        for i, label in enumerate(self.tx_labels):
            if i < len(txs):
                tx = txs[i]
                is_deposit = tx["to"] == self.run_config.get("pub", "")
                direction = "입금" if is_deposit else "출금"
                color = "#A7F3D0" if is_deposit else "#FCA5A5"

                try:
                    short_date = tx["date"][5:16].replace("-", "/")
                except Exception:
                    short_date = tx["date"]

                amount = Decimal(str(tx["amount"]))
                label.configure(
                    text=f"{short_date} | {direction} | {quantize_pi(amount)} PI",
                    text_color=color,
                )
            else:
                label.configure(text="-", text_color="gray")

    # ==============================
    # 시작 / 중지
    # ==============================
    def start_bot(self):
        try:
            self.run_config = {
                "pub": self.entry_pub.get().strip(),
                "sec": self.entry_sec.get().strip(),
                "target": self.entry_target.get().strip(),
                "min_pi": Decimal(self.entry_min_pi.get().strip()),
                "interval": int(self.entry_interval.get().strip()),
                "mode": self.transfer_mode.get(),
                "fixed_amt": Decimal(self.entry_fixed.get().strip()),
            }

            if not self.run_config["pub"]:
                raise ValueError("내 Pi 지갑 주소는 필수입니다.")
            if not self.run_config["sec"]:
                raise ValueError("24단어 구절은 필수입니다.")
            if not self.run_config["target"]:
                raise ValueError("목적지 지갑 주소는 필수입니다.")
            if self.run_config["interval"] < 1:
                raise ValueError("조회 주기는 최소 1초 이상이어야 합니다.")
            if self.run_config["min_pi"] <= 0:
                raise ValueError("작동 조건 금액은 0보다 커야 합니다.")
            if self.run_config["fixed_amt"] <= 0:
                raise ValueError("고정 송금 수량은 0보다 커야 합니다.")

            self.validate_public_key(self.run_config["pub"], "내 Pi 지갑 주소")
            self.validate_public_key(self.run_config["target"], "목적지 지갑 주소")

            kp, method, path = self.get_keypair_from_input(self.run_config["sec"], self.run_config["pub"])

            if kp.public_key != self.run_config["pub"]:
                raise ValueError("송금 차단: 24단어에서 파생된 주소가 내 지갑 주소와 다릅니다.")

            self.active_keypair = kp
            self.active_derivation_path = path

        except Exception as e:
            messagebox.showerror("시작 불가", str(e))
            return

        self.is_running = True
        self.toggle_ui(True)
        self.lbl_balance.configure(text="조회 대기중...")

        self.log("=========================================")
        self.log("🚀 Pi 24단어 자동 감시 시스템 가동")
        self.log("▶ bip-utils 미사용 / Pi 경로 자동 스캔 빌드")
        self.log(f"▶ Network Passphrase: {PI_NETWORK_PASSPHRASE}")
        self.log(f"▶ 내 주소: {short_key(self.run_config['pub'])}")
        self.log(f"▶ 목적지: {short_key(self.run_config['target'])}")
        self.log(f"▶ 파생 경로: {self.active_derivation_path}")
        self.log(f"▶ 감시 주기: {self.run_config['interval']}초")
        self.log(f"▶ 조건: {self.run_config['min_pi']} PI 이상")
        self.log("=========================================")

        threading.Thread(target=self.monitor_thread, daemon=True).start()

    def stop_bot(self, is_error=False):
        self.is_running = False
        self.after(0, lambda: self.toggle_ui(False))
        if is_error:
            self.log("[SYSTEM] 에러로 인해 감시를 자동 중단합니다.")
        else:
            self.log("[SYSTEM] 사용자 요청으로 감시를 중단했습니다.")

    # ==============================
    # 네트워크 조회
    # ==============================
    def fetch_recent_tx(self, pub_key):
        try:
            ops = self.server.payments().for_account(pub_key).order(desc=True).limit(12).call()
            tx_list = []

            for record in ops.get("_embedded", {}).get("records", []):
                if record.get("type") == "payment" and record.get("asset_type") == "native":
                    dt = record.get("created_at", "").replace("T", " ").replace("Z", "")
                    tx_list.append(
                        {
                            "date": dt,
                            "from": record.get("from", ""),
                            "to": record.get("to", ""),
                            "amount": record.get("amount", "0"),
                        }
                    )
                if len(tx_list) >= 5:
                    break

            return tx_list
        except Exception as e:
            self.log(f"[최근 거래 조회 실패] {str(e)}")
            return []

    def get_native_balance(self, pub_key) -> Decimal:
        account = self.server.accounts().account_id(pub_key).call()

        for b in account.get("balances", []):
            if b.get("asset_type") == "native":
                return Decimal(str(b.get("balance", "0")))

        return Decimal("0")

    # ==============================
    # 트랜잭션 제출/확인 유틸
    # ==============================
    def account_exists(self, pub_key: str) -> bool:
        try:
            self.server.accounts().account_id(pub_key).call()
            return True
        except Exception:
            return False

    def get_transaction_hash_from_envelope(self, transaction) -> str:
        """
        SDK 버전에 따라 TransactionEnvelope의 hash API 이름/반환형이 다를 수 있어
        가능한 방식을 순서대로 시도합니다.
        """
        # py-stellar-base 계열에서 흔한 메서드
        for attr in ("hash_hex",):
            try:
                method = getattr(transaction, attr, None)
                if callable(method):
                    value = method()
                    if value:
                        return str(value)
            except Exception:
                pass

        # TransactionEnvelope.hash()가 bytes를 반환하는 경우
        try:
            method = getattr(transaction, "hash", None)
            if callable(method):
                value = method()
                if isinstance(value, bytes):
                    return value.hex()
                if value:
                    return str(value)
        except Exception:
            pass

        return ""

    def extract_hash_from_submit_response(self, response) -> str:
        """
        Horizon 정상 submit 응답은 보통 hash를 포함합니다.
        Pi Horizon 또는 SDK/엔드포인트 차이로 id/hash가 다른 키에 있을 수 있어 보조 키도 확인합니다.
        """
        if isinstance(response, dict):
            for key in ("hash", "id", "transaction_hash", "tx_hash"):
                value = response.get(key)
                if value:
                    return str(value)

            # 일부 응답이 nested 형태일 가능성 대비
            result = response.get("result")
            if isinstance(result, dict):
                for key in ("hash", "id", "transaction_hash", "tx_hash"):
                    value = result.get(key)
                    if value:
                        return str(value)

        return ""

    def summarize_submit_response(self, response, max_len: int = 1200) -> str:
        try:
            text = json.dumps(response, ensure_ascii=False, indent=2)
        except Exception:
            text = repr(response)

        if len(text) > max_len:
            return text[:max_len] + "...(truncated)"
        return text

    def wait_for_transaction_confirmed(self, tx_hash: str, timeout_sec: int = TX_CONFIRM_TIMEOUT_SEC):
        """
        submit 응답만 믿지 않고 Horizon의 transaction endpoint에서 실제 반영 여부를 확인합니다.
        확인되면 transaction record dict를 반환하고, 실패하면 None을 반환합니다.
        """
        if not tx_hash:
            return None

        started = time.time()
        last_error = ""

        while time.time() - started < timeout_sec:
            if not self.is_running:
                return None

            try:
                tx_record = self.server.transactions().transaction(tx_hash).call()
                if isinstance(tx_record, dict) and tx_record.get("hash"):
                    return tx_record
            except Exception as e:
                last_error = str(e)

            time.sleep(TX_CONFIRM_POLL_INTERVAL_SEC)

        if last_error:
            self.log(f"⏳ TX 확인 마지막 오류: {last_error}")
        return None

    def get_recommended_base_fee_stroops(self) -> int:
        """
        Pi Horizon fee_stats를 우선 사용하고, 실패하면 안전 기본값 0.01 PI를 사용합니다.
        tx_insufficient_fee 방지를 위해 최소값을 MIN_BASE_FEE_STROOPS로 올립니다.
        """
        candidates = []

        # 1) stellar-sdk helper가 있으면 사용
        try:
            fetch_base_fee = getattr(self.server, "fetch_base_fee", None)
            if callable(fetch_base_fee):
                value = int(fetch_base_fee())
                if value > 0:
                    candidates.append(value)
        except Exception as e:
            self.log(f"fee helper 조회 실패: {str(e)}")

        # 2) Horizon fee_stats 직접 조회
        try:
            fee_stats_method = getattr(self.server, "fee_stats", None)
            if callable(fee_stats_method):
                stats = fee_stats_method().call()
                if isinstance(stats, dict):
                    for key in (
                        "last_ledger_base_fee",
                        "min_accepted_fee",
                        "mode_accepted_fee",
                        "p50_accepted_fee",
                        "p90_accepted_fee",
                        "p95_accepted_fee",
                        "p99_accepted_fee",
                        "max_fee",
                    ):
                        value = stats.get(key)
                        if value is not None:
                            try:
                                ivalue = int(value)
                                if ivalue > 0:
                                    candidates.append(ivalue)
                            except Exception:
                                pass
        except Exception as e:
            self.log(f"fee_stats 조회 실패: {str(e)}")

        if not candidates:
            fee = DEFAULT_BASE_FEE_STROOPS
        else:
            # 혼잡 시에도 통과되도록 확인된 후보 중 높은 값을 사용하고 2배 여유를 둡니다.
            fee = max(candidates) * 2

        fee = max(fee, MIN_BASE_FEE_STROOPS)
        fee = min(fee, MAX_BASE_FEE_STROOPS)
        return int(fee)

    def build_payment_transaction(self, source_pub: str, target_pub: str, amount_str: str):
        network = Network(PI_NETWORK_PASSPHRASE)
        source_account = self.server.load_account(source_pub)

        base_fee_stroops = self.get_recommended_base_fee_stroops()
        self.log(
            f"수수료 bid: {base_fee_stroops} stroops "
            f"({quantize_pi(stroops_to_pi(base_fee_stroops))} PI)"
        )

        return (
            TransactionBuilder(
                source_account=source_account,
                network_passphrase=network.network_passphrase,
                base_fee=base_fee_stroops,
            )
            .append_payment_op(
                destination=target_pub,
                asset=Asset.native(),
                amount=amount_str,
            )
            .set_timeout(60)
            .build()
        )

    # ==============================
    # 감시 / 송금
    # ==============================
    def monitor_thread(self):
        pub = self.run_config["pub"]
        target = self.run_config["target"]
        min_pi = self.run_config["min_pi"]
        interval = self.run_config["interval"]

        while self.is_running:
            try:
                pi_balance = self.get_native_balance(pub)
                txs = self.fetch_recent_tx(pub)

                self.after(0, lambda b=pi_balance, t=txs: self.update_dashboard(b, t))
                self.log(f"잔고 스캔 완료: {quantize_pi(pi_balance)} PI")

                if pi_balance >= min_pi:
                    self.log(f"🔔 조건 감지: {quantize_pi(pi_balance)} PI >= {quantize_pi(min_pi)} PI")

                    if self.run_config["mode"] == 1:
                        amount_to_send = pi_balance - PI_SAFE_RESERVE
                    else:
                        amount_to_send = self.run_config["fixed_amt"]

                    amount_to_send = amount_to_send.quantize(Decimal("0.0000001"), rounding=ROUND_DOWN)

                    if amount_to_send <= 0:
                        self.log("⚠️ 송금 가능 금액이 0 이하라서 스킵합니다.")
                    elif amount_to_send + PI_SAFE_RESERVE > pi_balance and self.run_config["mode"] == 2:
                        self.log("⚠️ 고정 송금 수량 + 안전 여유분이 잔고보다 커서 스킵합니다.")
                    else:
                        success = self.execute_transfer(pub, target, amount_to_send)
                        if success:
                            self.log("다음 스캔 전 대기 중... 15초")
                            for _ in range(15):
                                if not self.is_running:
                                    break
                                time.sleep(1)

            except Exception as e:
                self.log(f"[조회/네트워크 오류] {str(e)}")
                self.stop_bot(is_error=True)
                break

            for _ in range(interval):
                if not self.is_running:
                    break
                time.sleep(1)

    def execute_transfer(self, source_pub, target_pub, amount: Decimal):
        try:
            if self.active_keypair is None:
                raise ValueError("활성 키페어가 없습니다. 감시를 다시 시작하세요.")

            if self.active_keypair.public_key != source_pub:
                raise ValueError("서명 키와 내 지갑 주소가 다릅니다. 송금을 차단했습니다.")

            self.validate_public_key(target_pub, "목적지 지갑 주소")

            if source_pub == target_pub:
                raise ValueError("내 지갑 주소와 목적지 주소가 같습니다. 자기 자신에게 송금할 수 없습니다.")

            # 목적지 계정이 Horizon에서 조회되지 않으면 일반 payment op는 실패합니다.
            # 이 경우 create_account op가 필요하지만, 자동 생성은 자산 손실/오입금 위험이 있어 차단합니다.
            if not self.account_exists(target_pub):
                raise ValueError(
                    "목적지 계정이 Pi Horizon에서 조회되지 않습니다. "
                    "미활성 지갑에는 일반 payment 송금이 실패합니다. "
                    "목적지 주소가 활성화된 Pi 지갑인지 먼저 확인하세요."
                )

            amount_str = quantize_pi(amount)
            if Decimal(amount_str) <= 0:
                raise ValueError("송금 수량이 0 이하입니다.")

            before_balance = self.get_native_balance(source_pub)
            self.log(f"송금 전 잔고 확인: {quantize_pi(before_balance)} PI")

            if before_balance < Decimal(amount_str):
                raise ValueError("송금 전 잔고가 송금액보다 작습니다.")

            transaction = self.build_payment_transaction(source_pub, target_pub, amount_str)
            transaction.sign(self.active_keypair)

            local_hash = self.get_transaction_hash_from_envelope(transaction)
            if local_hash:
                self.log(f"로컬 TX Hash: {local_hash}")

            self.log("트랜잭션 제출 중...")
            response = self.server.submit_transaction(transaction)

            # Horizon이 400 transaction_failed를 dict로 반환하는 SDK/환경이 있어 직접 검사합니다.
            if isinstance(response, dict) and response.get("status") == 400:
                result_codes = response.get("extras", {}).get("result_codes", {})
                tx_code = result_codes.get("transaction", "")
                op_codes = result_codes.get("operations", [])
                self.log(f"❌ Horizon transaction_failed: {result_codes}")
                if tx_code == "tx_insufficient_fee":
                    raise ValueError(
                        "수수료 부족(tx_insufficient_fee)으로 거부되었습니다. "
                        "수수료 bid를 올려 다시 시도하세요."
                    )
                raise ValueError(f"Horizon이 트랜잭션을 거부했습니다: transaction={tx_code}, operations={op_codes}")

            response_hash = self.extract_hash_from_submit_response(response)
            tx_hash = response_hash or local_hash

            # hash가 없는 응답은 성공으로 처리하지 않습니다.
            if not tx_hash:
                self.log("❌ Horizon 응답에 TX Hash가 없습니다. 성공으로 처리하지 않습니다.")
                self.log(f"응답 요약: {self.summarize_submit_response(response)}")
                raise ValueError("트랜잭션 제출 응답에 hash가 없어 실제 반영 여부를 확인할 수 없습니다.")

            if response_hash:
                self.log(f"제출 응답 TX Hash: {response_hash}")
            else:
                self.log("⚠️ 제출 응답에는 hash가 없어서 로컬 계산 hash로 반영 여부를 확인합니다.")

            self.log("Horizon 반영 확인 중...")
            tx_record = self.wait_for_transaction_confirmed(tx_hash)

            if not tx_record:
                self.log(f"❌ TX가 {TX_CONFIRM_TIMEOUT_SEC}초 내 Horizon에서 확인되지 않았습니다.")
                self.log(f"응답 요약: {self.summarize_submit_response(response)}")
                raise ValueError("트랜잭션이 제출되었을 수 있으나 Horizon 반영 확인에 실패했습니다. 반복 송금을 막기 위해 중단합니다.")

            after_balance = self.get_native_balance(source_pub)
            self.after(0, lambda b=after_balance, t=self.fetch_recent_tx(source_pub): self.update_dashboard(b, t))

            self.log(f"✅ 송금 확정: {amount_str} PI")
            self.log(f"TX Hash: {tx_hash}")
            self.log(f"송금 후 잔고: {quantize_pi(after_balance)} PI")

            # 잔고 변화가 없는 경우도 확정 로그와 별도로 경고합니다.
            if after_balance == before_balance:
                self.log("⚠️ TX는 확인됐지만 잔고 변화가 감지되지 않았습니다. Horizon 최신 반영 지연 또는 다른 계정/금액 조건을 확인하세요.")

            return True

        except Exception as e:
            self.log(f"❌ [송금 실패] {str(e)}")
            self.stop_bot(is_error=True)
            return False


if __name__ == "__main__":
    app = PiEnterpriseBot()
    app.mainloop()
