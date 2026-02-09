#!/usr/bin/env python3
"""
Quick debug script to check poll messages and insert a test one.

Usage:
    python scripts/test_poll.py check <account_name>
    python scripts/test_poll.py insert <account_name> "Test message text"
    python scripts/test_poll.py count <account_name>
    python scripts/test_poll.py sessions
    python scripts/test_poll.py direct_poll <account_name>
"""

import asyncio
import sys
import os
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.connection import initialize_pool, get_pool


async def check_messages(account_name: str):
    """Check unread messages for an account."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT m.msg_id, m.msg_account_id, m.msg_date, m.msg_text, m.msg_lang, m.msg_read
            FROM messages m
            JOIN accounts a ON a.acc_id = m.msg_account_id
            WHERE UPPER(a.acc_name) = UPPER(:name)
            ORDER BY m.msg_date DESC
            FETCH FIRST 20 ROWS ONLY
        """, {"name": account_name})
        rows = cursor.fetchall()
        cursor.close()

        if not rows:
            print(f"No messages found for account '{account_name}'")
            cursor2 = conn.cursor()
            cursor2.execute(
                "SELECT acc_id, acc_name FROM accounts WHERE UPPER(acc_name) LIKE UPPER(:name)",
                {"name": f"%{account_name}%"}
            )
            accs = cursor2.fetchall()
            cursor2.close()
            if accs:
                print(f"  Matching accounts:")
                for acc in accs:
                    print(f"    id={acc[0]}, name={acc[1]}")
            else:
                print(f"  No accounts matching '{account_name}'")
            return

        print(f"Messages for account '{account_name}':")
        for row in rows:
            read_status = "READ" if row[5] == 1 else "UNREAD"
            print(f"  [{read_status}] id={row[0]} date={row[2]} lang={row[4]}")
            print(f"    {row[3]}")


async def count_messages(account_name: str):
    """Count unread messages using test_util."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        cursor = conn.cursor()
        result = cursor.var(int)
        cursor.execute("""
            DECLARE
                l_count INTEGER;
            BEGIN
                l_count := test_util.unread_message_count(:account);
                :result := l_count;
            END;
        """, {"account": account_name, "result": result})
        count = result.getvalue()
        cursor.close()
        print(f"Unread message count for '{account_name}': {count}")


async def insert_message(account_name: str, text: str):
    """Insert a test message directly."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        cursor = conn.cursor()
        # Find account ID
        cursor.execute(
            "SELECT acc_id FROM accounts WHERE acc_name = :name",
            {"name": account_name}
        )
        row = cursor.fetchone()
        if not row:
            print(f"Account '{account_name}' not found")
            cursor.close()
            return
        acc_id = row[0]

        # Try message.send() first, fall back to direct INSERT
        try:
            cursor.execute("""
                BEGIN
                    message.send(
                        message    => :text,
                        lang       => 'en',
                        account_id => :acc_id
                    );
                END;
            """, {"text": text, "acc_id": acc_id})
            conn.commit()
            print(f"Inserted message via message.send() for account '{account_name}' (id={acc_id})")
        except Exception as e:
            print(f"message.send() failed: {e}")
            print("Trying direct INSERT...")
            cursor.execute("""
                INSERT INTO messages (msg_id, msg_account_id, msg_date, msg_text, msg_lang, msg_read)
                VALUES (msg_id_seq.NEXTVAL, :acc_id, SYSDATE, :text, 'en', 0)
            """, {"acc_id": acc_id, "text": text})
            conn.commit()
            print(f"Inserted message via direct INSERT for account '{account_name}' (id={acc_id})")
        cursor.close()


async def check_sessions():
    """Check active EPP sessions/connections."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.cnn_id, c.cnn_status, c.cnn_client_ip, c.cnn_account_id,
                   s.ses_id, s.ses_status,
                   a.acc_name, a.acc_id
            FROM connections c
            LEFT JOIN sessions s ON s.ses_connection_id = c.cnn_id
            LEFT JOIN accounts a ON a.acc_id = c.cnn_account_id
            WHERE c.cnn_status = 'A' OR s.ses_status = 'A'
            ORDER BY c.cnn_id DESC
            FETCH FIRST 20 ROWS ONLY
        """)
        rows = cursor.fetchall()
        cursor.close()
        if not rows:
            print("No active sessions found")
            return
        print("Active EPP sessions:")
        for row in rows:
            print(f"  conn={row[0]} conn_status={row[1]} ip={row[2]} conn_acc={row[3]} "
                  f"ses={row[4]} ses_status={row[5]} acc_name={row[6]} acc_id={row[7]}")


async def direct_poll(account_name: str):
    """Call epp.poll() directly with a known connection/session to debug."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        cursor = conn.cursor()
        # Find active session for this account
        cursor.execute("""
            SELECT c.cnn_id, s.ses_id, a.acc_name, a.acc_id
            FROM connections c
            JOIN sessions s ON s.ses_connection_id = c.cnn_id
            JOIN accounts a ON a.acc_id = c.cnn_account_id
            WHERE UPPER(a.acc_name) LIKE UPPER(:name)
              AND (c.cnn_status = 'A' OR s.ses_status = 'A')
            ORDER BY s.ses_id DESC
            FETCH FIRST 5 ROWS ONLY
        """, {"name": f"%{account_name}%"})
        rows = cursor.fetchall()
        if not rows:
            print(f"No active sessions for '{account_name}'")
            # Check unread count directly
            cursor.execute("""
                SELECT COUNT(*) FROM messages m
                JOIN accounts a ON a.acc_id = m.msg_account_id
                WHERE UPPER(a.acc_name) LIKE UPPER(:name) AND m.msg_read = 0
            """, {"name": f"%{account_name}%"})
            cnt = cursor.fetchone()[0]
            print(f"  But there are {cnt} unread messages in the DB")
            cursor.close()
            return

        for row in rows:
            conn_id, ses_id, acc_name, acc_id = row
            print(f"Trying poll with conn={conn_id}, ses={ses_id}, acc={acc_name} (id={acc_id})")

            response_code = cursor.var(int)
            response_msg = cursor.var(str, 4000)
            msgq_count = cursor.var(int)
            msgq_id = cursor.var(int)

            try:
                cursor.execute("""
                    DECLARE
                        l_response epp_response_t;
                        l_resdata  epp_poll_resdata_t;
                    BEGIN
                        epp.poll(
                            connection_id => :connection_id,
                            session_id    => :session_id,
                            op            => 'req',
                            msgid         => NULL,
                            cltrid        => 'test-poll-debug',
                            response      => l_response,
                            resdata       => l_resdata
                        );
                        IF l_response.result IS NOT NULL AND l_response.result.COUNT > 0 THEN
                            :rc := l_response.result(1).code;
                            IF l_response.result(1).msg IS NOT NULL THEN
                                :msg := l_response.result(1).msg.string;
                            END IF;
                        END IF;
                        IF l_response.msgq IS NOT NULL THEN
                            :mcount := l_response.msgq.count;
                            :mid := l_response.msgq.id;
                        END IF;
                    END;
                """, {
                    "connection_id": conn_id,
                    "session_id": ses_id,
                    "rc": response_code,
                    "msg": response_msg,
                    "mcount": msgq_count,
                    "mid": msgq_id,
                })
                rc = response_code.getvalue()
                msg = response_msg.getvalue()
                mc = msgq_count.getvalue()
                mi = msgq_id.getvalue()
                print(f"  Result: code={rc}, msg={msg}, msgq_count={mc}, msgq_id={mi}")
            except Exception as e:
                print(f"  Error: {e}")

        cursor.close()


async def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    action = sys.argv[1]
    account = sys.argv[2] if len(sys.argv) > 2 else None

    # Load config from YAML
    config_path = os.environ.get("EPP_CONFIG", "config/epp.yaml")
    with open(config_path) as f:
        config = yaml.safe_load(f)

    await initialize_pool(config.get("oracle") or config.get("database"))

    if action == "check":
        await check_messages(account)
    elif action == "count":
        await count_messages(account)
    elif action == "insert":
        text = sys.argv[3] if len(sys.argv) > 3 else "Test poll message"
        await insert_message(account, text)
    elif action == "sessions":
        await check_sessions()
    elif action == "direct_poll":
        await direct_poll(account)
    else:
        print(f"Unknown action: {action}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
