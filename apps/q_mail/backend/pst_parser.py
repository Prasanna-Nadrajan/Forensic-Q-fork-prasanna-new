"""
Q-Mail High-Performance PST Forensic Parser Engine
Powered by pypff (libpff-python-windows) for streaming 50+ GB PST files with zero dummy logic.
"""

import hashlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pypff
from loguru import logger


@dataclass
class ParsedAttachment:
    filename: str
    file_size_bytes: int
    mime_type: str
    file_extension: str
    sha256_hash: str
    storage_path: str


@dataclass
class ParsedEmail:
    message_id: str
    subject: str
    sender_name: str
    sender_email: str
    recipients_to: list[str] = field(default_factory=list)
    recipients_cc: list[str] = field(default_factory=list)
    recipients_bcc: list[str] = field(default_factory=list)
    sent_date: datetime | None = None
    delivery_date: datetime | None = None
    folder_path: str = ""
    body_plain: str = ""
    body_html: str = ""
    importance: int = 1
    conversation_topic: str = ""
    attachments: list[ParsedAttachment] = field(default_factory=list)


class PSTStreamParser:
    """
    Memory-efficient recursive PST stream parser capable of reading 50+ GB files.
    """

    def __init__(
        self,
        pst_path: Path | str,
        attachments_dir: Path | str | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
        check_cancellation_callback: Callable[[], bool] | None = None,
    ):
        self.pst_path = Path(pst_path)
        self.attachments_dir = Path(attachments_dir) if attachments_dir else None
        self.progress_callback = progress_callback
        self.check_cancellation_callback = check_cancellation_callback
        self.total_messages_processed = 0
        self.is_cancelled = False

    def parse_messages(self) -> Iterator[ParsedEmail]:
        """
        Opens the PST file via libpff and yields ParsedEmail objects.
        """
        if not str(self.pst_path).strip() or not self.pst_path.is_file():
            raise FileNotFoundError(
                f"PST evidence file not found or path is not a file: '{self.pst_path}'"
            )

        pst_file = pypff.file()
        pst_file.open(str(self.pst_path))

        try:
            root_folder = pst_file.get_root_folder()
            if root_folder:
                yield from self._traverse_folder(root_folder, current_path="")
        finally:
            pst_file.close()

    def _traverse_folder(self, folder: Any, current_path: str) -> Iterator[ParsedEmail]:
        """
        Recursively processes folder messages and sub-folders with cancellation checks.
        """
        if self.is_cancelled or (
            self.check_cancellation_callback and self.check_cancellation_callback()
        ):
            self.is_cancelled = True
            logger.info("PST Stream parser received cancellation signal during traversal.")
            return

        folder_name = folder.get_name() or "Root"
        full_path = f"{current_path}/{folder_name}".strip("/")

        num_sub_messages = folder.get_number_of_sub_messages()

        if self.progress_callback:
            self.progress_callback(full_path, self.total_messages_processed, num_sub_messages)

        # Process all messages in current folder
        for i in range(num_sub_messages):
            if self.is_cancelled or (
                self.check_cancellation_callback and self.check_cancellation_callback()
            ):
                self.is_cancelled = True
                logger.info("PST Stream parser aborted message loop on cancellation request.")
                return

            try:
                message = folder.get_sub_message(i)
                if message:
                    parsed_email = self._extract_message(message, full_path)
                    self.total_messages_processed += 1
                    yield parsed_email
            except Exception as e:
                # Corrupted or unreadable message block: log and continue streaming without crashing
                logger.warning("Failed to parse message %d in folder %s: %s", i, full_path, e)

        # Recurse into sub-folders
        num_sub_folders = folder.get_number_of_sub_folders()
        for j in range(num_sub_folders):
            if self.is_cancelled or (
                self.check_cancellation_callback and self.check_cancellation_callback()
            ):
                self.is_cancelled = True
                return

            try:
                sub_folder = folder.get_sub_folder(j)
                if sub_folder:
                    yield from self._traverse_folder(sub_folder, full_path)
            except Exception as e:
                logger.warning("Failed to traverse sub-folder %d in %s: %s", j, full_path, e)

    def _extract_message(self, msg: Any, folder_path: str) -> ParsedEmail:
        """
        Extracts all attributes, timestamps, recipients, and attachments from a pypff message.
        """
        # Subject
        try:
            subject = msg.get_subject() or ""
        except Exception:
            subject = "(Unreadable Subject)"

        # Sender
        try:
            sender_name = msg.get_sender_name() or ""
        except Exception:
            sender_name = ""

        try:
            # Transport headers or sender email
            sender_email = msg.get_sender_email_address() or sender_name
        except Exception:
            sender_email = sender_name

        # Message ID & Topic
        try:
            conversation_topic = msg.get_conversation_topic() or subject
        except Exception:
            conversation_topic = subject

        # Sent / Delivery Timestamps
        sent_date = self._get_datetime(msg.get_client_submit_time())
        delivery_date = self._get_datetime(msg.get_delivery_time())

        # Body Text
        body_plain = ""
        try:
            plain_bytes = msg.get_plain_text_body()
            if plain_bytes:
                body_plain = plain_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_plain = ""

        body_html = ""
        try:
            html_bytes = msg.get_html_body()
            if html_bytes:
                body_html = html_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_html = ""

        # Importance
        try:
            importance = msg.get_importance() or 1
        except Exception:
            importance = 1

        # Recipients
        recipients_to = []
        recipients_cc = []
        recipients_bcc = []

        try:
            num_recipients = msg.get_number_of_recipients()
            for r_idx in range(num_recipients):
                recipient = msg.get_recipient(r_idx)
                if recipient:
                    r_name = recipient.get_name() or ""
                    r_email = recipient.get_email_address() or r_name
                    # Type: 1 = To, 2 = CC, 3 = BCC
                    recip_type = getattr(recipient, "type", 1)
                    formatted_r = (
                        f"{r_name} <{r_email}>" if r_name and r_name != r_email else r_email
                    )

                    if recip_type == 2:
                        recipients_cc.append(formatted_r)
                    elif recip_type == 3:
                        recipients_bcc.append(formatted_r)
                    else:
                        recipients_to.append(formatted_r)
        except Exception as e:
            logger.debug("Failed extracting recipients: %s", e)

        # Unique synthetic Message ID if not present in transport headers
        msg_hash = hashlib.sha256(f"{sender_email}:{subject}:{sent_date}".encode()).hexdigest()
        message_id = f"<{msg_hash[:24]}@pst.audit>"

        # Attachments Extraction
        attachments = []
        try:
            num_attachments = msg.get_number_of_attachments()
            for a_idx in range(num_attachments):
                att = msg.get_attachment(a_idx)
                if att:
                    extracted_att = self._extract_attachment(att, msg_hash[:16])
                    if extracted_att:
                        attachments.append(extracted_att)
        except Exception as e:
            logger.debug("Failed extracting attachments for message %s: %s", message_id, e)

        return ParsedEmail(
            message_id=message_id,
            subject=subject,
            sender_name=sender_name,
            sender_email=sender_email,
            recipients_to=recipients_to,
            recipients_cc=recipients_cc,
            recipients_bcc=recipients_bcc,
            sent_date=sent_date,
            delivery_date=delivery_date,
            folder_path=folder_path,
            body_plain=body_plain,
            body_html=body_html,
            importance=importance,
            conversation_topic=conversation_topic,
            attachments=attachments,
        )

    def _extract_attachment(self, att: Any, email_hash: str) -> ParsedAttachment | None:
        """
        Saves physical attachment file to evidence directory and computes SHA-256 hash.
        """
        try:
            # Libpff attachments use get_long_filename(), not get_name()
            filename = ""
            if hasattr(att, "get_long_filename"):
                filename = att.get_long_filename()

            # Fallback to MAPI properties (0x3707, 0x3704, or 0x3001) if get_long_filename is None
            is_embedded_msg = False
            if hasattr(att, "get_number_of_record_sets"):
                try:
                    display_name = ""
                    for r in range(att.get_number_of_record_sets()):
                        rs = att.get_record_set(r)
                        for e in range(rs.get_number_of_entries()):
                            entry = rs.get_entry(e)
                            if entry.entry_type == 0x3705:  # PR_ATTACH_METHOD
                                data = entry.get_data()
                                if data and len(data) >= 4:
                                    method = int.from_bytes(data[:4], "little")
                                    if method == 5:  # ATTACH_EMBEDDED_MSG
                                        is_embedded_msg = True
                            elif entry.entry_type in (0x3707, 0x3704, 0x3001):
                                data = entry.get_data()
                                if data:
                                    decoded = data.decode("utf-16le", errors="ignore").replace(
                                        "\x00", ""
                                    )
                                    if decoded:
                                        if entry.entry_type in (0x3707, 0x3704):
                                            filename = decoded
                                        elif entry.entry_type == 0x3001:
                                            display_name = decoded
                    if not filename and display_name:
                        filename = display_name
                except Exception as ex:
                    logger.debug("Failed extracting filename from MAPI: %s", ex)

            filename = filename or f"attachment_{email_hash}"
            if is_embedded_msg and not filename.lower().endswith(".msg"):
                # Clean invalid chars in case display name has them
                import re

                filename = re.sub(r'[\\/*?:"<>|]', "", filename)
                filename = f"{filename}.msg"

            file_size = att.get_size() or 0
            file_extension = Path(filename).suffix.lower()

            sha256_hash = ""
            storage_path = ""

            # If attachments directory is configured, stream file to disk
            if self.attachments_dir:
                dest_dir = self.attachments_dir / email_hash
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_file = dest_dir / filename

                hasher = hashlib.sha256()
                with open(dest_file, "wb") as f:
                    read_offset = 0
                    if hasattr(att, "seek_offset"):
                        att.seek_offset(0, 0)

                    while read_offset < file_size:
                        chunk_size = min(65536, file_size - read_offset)
                        # read_buffer accepts exactly 1 argument in libpff
                        data = att.read_buffer(chunk_size)
                        if not data:
                            break
                        f.write(data)
                        hasher.update(data)
                        read_offset += len(data)

                sha256_hash = hasher.hexdigest()
                storage_path = str(dest_file)
            else:
                sha256_hash = hashlib.sha256(filename.encode("utf-8")).hexdigest()

            return ParsedAttachment(
                filename=filename,
                file_size_bytes=file_size,
                mime_type=self._guess_mime(file_extension),
                file_extension=file_extension,
                sha256_hash=sha256_hash,
                storage_path=storage_path,
            )
        except Exception as e:
            logger.exception("Failed saving attachment for email %s: %s", email_hash, e)
            return None

    @staticmethod
    def _get_datetime(pypff_time: Any) -> datetime | None:
        """
        Converts pypff datetime objects to Python timezone-aware datetime.
        """
        if not pypff_time:
            return None
        try:
            if isinstance(pypff_time, datetime):
                if pypff_time.tzinfo is None:
                    return pypff_time.replace(tzinfo=UTC)
                return pypff_time
            return datetime.fromtimestamp(pypff_time, tz=UTC)
        except Exception as e:
            logger.debug("Failed converting timestamp %s: %s", pypff_time, e)
            return None

    @staticmethod
    def _guess_mime(ext: str) -> str:
        mime_map = {
            ".pdf": "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".zip": "application/zip",
            ".eml": "message/rfc822",
            ".msg": "application/vnd.ms-outlook",
            ".png": "image/png",
            ".jpg": "image/jpeg",
        }
        return mime_map.get(ext, "application/octet-stream")
