# app.py
import base64
import re
import requests
import urllib3
import logging
import json
from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 禁用InsecureRequestWarning警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
    handlers=[
        #logging.FileHandler("decryption_app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 初始化 Flask 应用
app = Flask(__name__)


# --- JSON修复和AES解密函数 (无变化) ---
def repair_and_format_json(text_content: str) -> str:
    # ... 此函数内容无变化, 为保持完整性而保留 ...
    logger.info("启动最终版JSON格式化修复流程(带协议修正)...")
    content = text_content.strip()
    first_comma_index = content.find(',')
    if first_comma_index != -1:
        prefix = content[:first_comma_index]
        spider_match = re.search(r'([a-zA-Z]+://.*?;md5;[a-fA-F0-9]{32})', prefix)
        if spider_match:
            spider_value = spider_match.group(1)
            logger.info(f"策略〇：检测到 'URL;md5;hash' 模式。初步提取值为: {spider_value}")
            if '://' in spider_value:
                protocol, rest_of_url = spider_value.split('://', 1)
                if protocol not in ['http', 'https']:
                    original_protocol = protocol
                    if 'ttps' in protocol or protocol.endswith('tps'):
                        protocol = 'https'
                    elif 'http' in protocol:
                        protocol = 'http'
                    if protocol != original_protocol:
                        logger.warning(f"检测到并修正了不规范的协议：从 '{original_protocol}' 修改为 '{protocol}'。")
                        spider_value = f"{protocol}://{rest_of_url}"
            rest_of_content = content[first_comma_index:]
            repaired_content = f'{{"spider":"{spider_value}"{rest_of_content}'
            logger.debug("特殊修复后，内容已重构为标准JSON对象头。")
            content = repaired_content
        else:
            logger.info("策略〇：未在第一个逗号前找到 'URL;md5;hash' 模式，跳过特殊修复。")
    start_brace = content.find('{')
    start_bracket = content.find('[')
    start_index = -1
    if start_brace != -1 and (start_brace < start_bracket or start_bracket == -1):
        start_index = start_brace
    elif start_bracket != -1:
        start_index = start_bracket
    json_candidate = ""
    if start_index != -1:
        if start_index > 0:
            logger.warning(f"内容开头存在 {start_index} 个字符的非JSON内容，已自动跳过。")
        json_candidate = content[start_index:]
    else:
        logger.error("策略一失败：内容中未找到标准JSON起始符 '{' 或 '['。按原样返回。")
        return content
    try:
        closing_char = '}' if json_candidate.startswith('{') else ']'
        last_closing_index = json_candidate.rfind(closing_char)
        if last_closing_index != -1:
            cleaned_json = json_candidate[:last_closing_index + 1]
        else:
            cleaned_json = json_candidate
        data = json.loads(cleaned_json)
        formatted_json = json.dumps(data, indent=4, ensure_ascii=False)
        logger.info("JSON修复、解析和格式化成功！")
        return formatted_json
    except json.JSONDecodeError as e:
        logger.error(f"最终解析失败: {e}。返回尽力修复后的字符串。")
        return json_candidate


def decrypt_aes_payload(payload: str) -> str:
    # ... 此函数内容无变化, 为保持完整性而保留 ...
    logger.info("进入AES解密流程...")
    match = re.search(r"2423(.*?)2324(.*?)(?:3136|3137)(.*)", payload, re.DOTALL)
    if not match:
        error_msg = "AES加密数据格式不正确，未找到'2423...2324...(3136或3137)'结构。"
        logger.error(error_msg)
        raise ValueError(error_msg)
    hex_key_part, ciphertext_part, iv_part = match.groups()
    key_str = bytes.fromhex(hex_key_part).decode('utf-8', errors='ignore')
    key = key_str.ljust(16, '0').encode('utf-8')
    processed_iv_str = iv_part[:16].ljust(16, '0')
    iv = processed_iv_str.encode('utf-8')
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext_part)
    except ValueError:
        raise ValueError("密文部分不是有效的16进制字符串。")
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_bytes = cipher.decrypt(ciphertext_bytes)
        decrypted_bytes = unpad(decrypted_padded_bytes, AES.block_size)
        return decrypted_bytes.decode('utf-8', errors='ignore')
    except ValueError as e:
        raise ValueError(f"AES解密失败，请检查Key/IV或密文是否正确。错误: {e}")


# --- Flask 路由和视图 (★★★ 有重要修改 ★★★) ---
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    url_to_process = ''
    ignore_ssl_checked = True

    if request.method == 'POST':
        url_to_process = request.form.get('url', '')
        ignore_ssl_checked = 'ignore_ssl' in request.form
        should_verify_ssl = not ignore_ssl_checked

        logger.info(f"收到对URL的解密请求: {url_to_process}")
        logger.info(f"SSL证书验证: {'启用' if should_verify_ssl else '忽略'}")

        if not url_to_process:
            error = "请输入URL地址"
        else:
            try:
                headers = {
                    'User-Agent': 'okhttp/5.1.0'
                }
                logger.info(f"使用User-Agent: {headers['User-Agent']}")

                response = requests.get(
                    url_to_process,
                    timeout=15,
                    verify=should_verify_ssl,
                    headers=headers
                )

                response.raise_for_status()

                # ★★★ 核心逻辑修改开始 ★★★
                # 1. 统一将返回的二进制内容解码为字符串，忽略解码错误
                raw_text = response.content.decode('utf-8', errors='ignore')
                final_text = ""

                # 2. 在解码后的文本中直接搜索'**'特征
                if '**' in raw_text:
                    logger.info("在返回内容中找到 '**' 分隔符，按“图片藏数据”规则处理。")
                    # 3. 如果找到，分割字符串，取后半部分进行Base64解码
                    try:
                        base64_str = raw_text.split('**', 1)[1]
                        logger.info("开始对提取的内容进行Base64解码...")
                        decoded_bytes = base64.b64decode(base64_str)
                        final_text = decoded_bytes.decode('utf-8', errors='ignore')
                        logger.info("Base64解码成功。")
                    except (base64.binascii.Error, IndexError) as e:
                        raise ValueError(f"找到'**'但处理失败(可能是Base64格式错误): {e}")
                else:
                    # 4. 如果未找到，直接使用解码后的完整文本
                    logger.info("返回内容中未找到 '**' 分隔符，按普通文本处理。")
                    final_text = raw_text
                # ★★★ 核心逻辑修改结束 ★★★

                # --- 统一的任务分发中心 (此部分逻辑不变) ---
                if final_text.strip().startswith('2423'):
                    logger.info("检测到'2423'开头，进入AES解密流程。")
                    decrypted_text = decrypt_aes_payload(final_text)
                    logger.info("AES解密完成，进行JSON格式化。")
                    result = repair_and_format_json(decrypted_text)
                else:
                    logger.info("内容非'2423'开头，直接进行JSON格式化。")
                    result = repair_and_format_json(final_text)

                logger.info("解密流程处理完毕。")

            except requests.exceptions.SSLError as e:
                error = f"SSL证书验证失败: {e}。请尝试勾选'忽略SSL证书错误'后重试。"
                logger.error(f"对 {url_to_process} 的SSL验证失败。", exc_info=True)
            except requests.exceptions.RequestException as e:
                error = f"网络请求失败: {e}"
                logger.error(f"网络请求到 {url_to_process} 失败。", exc_info=True)
            except Exception as e:
                error = f"处理过程中发生错误: {e}"
                logger.error(f"在处理 {url_to_process} 时发生未知错误。", exc_info=True)
    else:
        # GET请求时，给一个默认的URL
        url_to_process = ''

    return render_template('index.html', url=url_to_process, result=result, error=error,
                           ignore_ssl_checked=ignore_ssl_checked)


if __name__ == '__main__':
    logger.info("Flask应用启动...")
    app.run(debug=True, host='0.0.0.0', use_reloader=False)

