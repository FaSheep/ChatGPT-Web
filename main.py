import datetime
import hashlib
import json
import random
import re
import string
import requests
import os
import uuid
import yaml
import io
import base64
from io import BytesIO
from flask import Flask, make_response, redirect, render_template, request, session
from sqlalchemy import create_engine, select
from sqlalchemy.orm import declarative_base, Session, relationship
from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.dialects.mysql import LONGTEXT
from PIL import Image, ImageFont, ImageDraw

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

with open("config.yaml", "r", encoding="utf-8") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
    if 'HTTPS_PROXY' in config:
        if os.environ.get('HTTPS_PROXY') is None:   # 优先使用环境变量中的代理，若环境变量中没有代理，则使用配置文件中的代理
            os.environ['HTTPS_PROXY'] = config['HTTPS_PROXY']
    PORT = config['PORT']
    API_KEY = config['OPENAI_API_KEY']
    CHAT_CONTEXT_NUMBER_MAX = config['CHAT_CONTEXT_NUMBER_MAX']     # 连续对话模式下的上下文最大数量 n，即开启连续对话模式后，将上传本条消息以及之前你和GPT对话的n-1条消息
    SQL_SEVER = config['SQL_SERVER']
    SQL_PORT = config['SQL_PORT']
    SQL_USERNAME = config['SQL_USERNAME']
    SQL_PASSWORD = config['SQL_PASSWORD']
    API_URL = config['API_URL']
    USER_BALANCE = config['USER_BALANCE']

url = API_URL + "/v1/chat/completions"
subscription_url = API_URL + "/v1/dashboard/billing/subscription"

if os.getenv("DEPLOY_ON_RAILWAY") is not None:  # 如果是在Railway上部署，需要删除代理
    os.environ.pop('HTTPS_PROXY', None)

API_KEY = os.getenv("OPENAI_API_KEY", default=API_KEY)  # 如果环境变量中设置了OPENAI_API_KEY，则使用环境变量中的OPENAI_API_KEY
PORT = os.getenv("PORT", default=PORT)  # 如果环境变量中设置了PORT，则使用环境变量中的PORT
SQL_SEVER = os.getenv("SQL_SERVER", default=SQL_SEVER)
SQL_PORT = os.getenv("SQL_PORT", default=SQL_PORT)
SQL_USERNAME = os.getenv("SQL_USERNAME", default=SQL_USERNAME)
SQL_PASSWORD = os.getenv("SQL_PASSWORD", default=SQL_PASSWORD)
USER_BALANCE = os.getenv("USER_BALANCE", default=USER_BALANCE) # 用户初始余额

STREAM_FLAG = True  # 是否开启流式推送

Base = declarative_base()
class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(16), unique=True)
    password = Column(String(64))
    balance = Column(Integer)
    chat = relationship(
        "Chat", back_populates="user", cascade="all, delete-orphan"
    )

    # def __repr__(self):
    #     return f"User(id={self.id!r}, username={self.username!r}, password={self.password!r})"

class Chat(Base):
    __tablename__ = "chat"
    id = Column(Integer, primary_key=True)
    name = Column(String(32))

    user_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    user = relationship("User", back_populates="chat")
    history = relationship(
        "History", back_populates="chat", cascade="all, delete-orphan"
    )

class History(Base):
    __tablename__ = "history"
    id = Column(Integer, primary_key=True)
    content = Column(LONGTEXT)
    role = Column(String(10))
    chat_id = Column(Integer, ForeignKey("chat.id"), nullable=False)

    chat = relationship("Chat", back_populates="history")

    # def __repr__(self):
    #     return f"{{\"content\":\"{self.content!r}\",\"role\":\"{self.role!r}\"}}"

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    value = Column(String(16), unique=True)
    balance = Column(Integer)

engine = create_engine(
    f"mysql+pymysql://{SQL_USERNAME}:{SQL_PASSWORD}@{SQL_SEVER}:{SQL_PORT}/chat?charset=utf8",
    echo = True,
    future=True
)

Base.metadata.create_all(bind=engine, checkfirst=True)

# 验证码实现类
class imageCode():
    def rndColor(self):
        '''随机颜色'''
        return (random.randint(32, 127), random.randint(32, 127), random.randint(32, 127))

    def geneText(self):
        '''生成4位验证码'''
        return ''.join(random.sample(string.ascii_letters + string.digits, 4)) #ascii_letters是生成所有字母 digits是生成所有数字0-9

    def drawLines(self, draw, num, width, height):
        '''划线'''
        for num in range(num):
            x1 = random.randint(0, width / 2)
            y1 = random.randint(0, height / 2)
            x2 = random.randint(0, width)
            y2 = random.randint(height / 2, height)
            draw.line(((x1, y1), (x2, y2)), fill='black', width=1)

    def getVerifyCode(self):
        '''生成验证码图形'''
        code = self.geneText()
        # 图片大小120×50
        width, height = 120, 50
        # 新图片对象
        im = Image.new('RGB', (width, height), 'white')
        # 字体
        font = ImageFont.truetype('static/arial.ttf', 40)
        # draw对象
        draw = ImageDraw.Draw(im)
        # 绘制字符串
        for item in range(4):
            draw.text((5 + random.randint(-3, 3) + 23 * item, 5 + random.randint(-3, 3)),
                    text=code[item], fill=self.rndColor(), font=font)
        # 划线
        self.drawLines(draw, 2, width, height)
        return im, code

    def getImgCode(self):
        image, code = self.getVerifyCode()
        # 将图片转换为byte类型的数据
        buf = io.BytesIO()
        image.save(buf, format='jpeg')
        buf_bytes = buf.getvalue()

        # 将 byte 类型转为 base64 字符串
        img_base64 = base64.b64encode(buf_bytes).decode('utf-8')

        # 返回包含base64格式图片字符串的response对象
        response = make_response(img_base64)
        response.headers['Content-Type'] = 'text/plain'
        
        # 将验证码字符串储存在session中
        session['imageCode'] = code
        return response

project_info = "## ChatGPT 网页版    \n" \
               " Code From  " \
               "[ChatGPT-Web](https://github.com/FaSheep/ChatGPT-Web)  \n"

def get_response_from_ChatGPT_API(message_context, apikey):
    """
    从ChatGPT API获取回复
    :param apikey:
    :param message_context: 上下文
    :return: 回复
    """
    if apikey is None:
        apikey = API_KEY

    header = {"Content-Type": "application/json",
              "Authorization": "Bearer " + apikey}

    data = {
        "model": "gpt-3.5-turbo",
        "messages": message_context
    }

    try:
        response = requests.post(url, headers=header, data=json.dumps(data))
        response = response.json()
        # 判断是否含 choices[0].message.content
        if "choices" in response \
                and len(response["choices"]) > 0 \
                and "message" in response["choices"][0] \
                and "content" in response["choices"][0]["message"]:
            data = response["choices"][0]["message"]["content"]
        else:
            data = str(response)

    except Exception as e:
        print(e)
        return str(e)

    return data


def get_message_context(message_history, have_chat_context, chat_with_history):
    """
    获取上下文
    :param message_history:
    :param have_chat_context:
    :param chat_with_history:
    :return:
    """
    message_context = []
    total = 0
    if chat_with_history:
        num = min([len(message_history), CHAT_CONTEXT_NUMBER_MAX, have_chat_context])
        # 获取所有有效聊天记录
        valid_start = 0
        valid_num = 0
        for i in range(len(message_history) - 1, -1, -1):
            message = message_history[i]
            if message['role'] in {'assistant', 'user'}:
                valid_start = i
                valid_num += 1
            if valid_num >= num:
                break

        for i in range(valid_start, len(message_history)):
            message = message_history[i]
            if message['role'] in {'assistant', 'user'}:
                message_context.append(message)
                total += len(message['content'])
    else:
        message_context.append(message_history[-1])
        total += len(message_history[-1]['content'])

    print(f"len(message_context): {len(message_context)} total: {total}",)
    return message_context


def handle_messages_get_response(message, send_time, user_id, chat_id, chat_with_history):
    """
    处理用户发送的消息，获取回复
    :param message: 用户发送的消息
    :param apikey:
    :param message_history: 消息历史
    :param have_chat_context: 已发送消息数量上下文(从重置为连续对话开始)
    :param chat_with_history: 是否连续对话
    """
    with Session(engine) as sqlsession:
        user = sqlsession.query(User).filter(User.id==user_id).one()
        if user.balance <= 0:
            return "余额不足"
        chat = sqlsession.query(Chat).filter(Chat.id==chat_id).one()
        if send_time != "":
            chat.history.append(History(content=send_time, role="system"))
        chat.history.append(History(content=message, role="user"))

        message_history = []
        have_chat_context = 0
        for h in chat.history:
            message_history.append({'role': h.role, 'content': h.content})
            if h.role in {'user', 'assistant'}:
                have_chat_context += 1
        message_context = get_message_context(message_history, have_chat_context, chat_with_history)
        response = get_response_from_ChatGPT_API(message_context, API_KEY)
        chat.history.append(History(content=response, role="assistant"))

        all_msg = str()
        for msg in message_context:
            all_msg += (msg['content'])
            all_msg += (' ')
        all_msg += (response)
        count = 0
        for s in all_msg:
            if '\u4e00' <= s <= '\u9fff':
                count += 1
        user.balance = max(user.balance - (len(response.split()) + count), 0)

        sqlsession.commit()

    return response


def get_response_stream_generate_from_ChatGPT_API(message_context, apikey, user_id, chat_id):
    """
    从ChatGPT API获取回复
    :param apikey:
    :param message_context: 上下文
    :return: 回复
    """
    if apikey is None:
        apikey = API_KEY

    header = {"Content-Type": "application/json",
              "Authorization": "Bearer " + apikey}

    data = {
        "model": "gpt-3.5-turbo",
        "messages": message_context,
        "stream": True
    }
    print("开始流式请求")
    # 请求接收流式数据 动态print
    try:
        response = requests.request("POST", url, headers=header, json=data, stream=True)

        def generate():
            stream_content = str()
            
            i = 0
            for line in response.iter_lines():
                line_str = str(line, encoding='utf-8')
                if line_str.startswith("data:"):
                    if line_str.startswith("data: [DONE]"):
                        break
                    line_json = json.loads(line_str[5:])
                    if 'choices' in line_json:
                        if len(line_json['choices']) > 0:
                            choice = line_json['choices'][0]
                            if 'delta' in choice:
                                delta = choice['delta']
                                if 'role' in delta:
                                    role = delta['role']
                                elif 'content' in delta:
                                    delta_content = delta['content']
                                    i += 1
                                    if i < 40:
                                        print(delta_content, end="")
                                    elif i == 40:
                                        print("......")
                                    stream_content += delta_content
                                    yield delta_content

                elif len(line_str.strip()) > 0:
                    print(line_str)
                    yield line_str
            with Session(engine) as sqlsession:
                if not stream_content=="":
                    all_msg = str()
                    for msg in message_context:
                        all_msg += msg['content']
                        all_msg += ' '
                    all_msg += stream_content
                    user = sqlsession.query(User).filter(User.id==user_id).one()
                    chat = sqlsession.query(Chat).filter(Chat.id==chat_id).one()
                    chat.history.append(History(content=stream_content, role="assistant"))
                    count = 0
                    for s in all_msg:
                        if '\u4e00' <= s <= '\u9fff':
                            count += 1
                    user.balance = max(user.balance - (len(stream_content.split()) + count), 0)
                    sqlsession.commit()

    except Exception as e:
        ee = e

        def generate():
            yield "request error:\n" + str(ee)

    return generate

def handle_messages_get_response_stream(message, send_time, user_id, chat_id, chat_with_history):
    with Session(engine) as sqlsession:
        user = sqlsession.query(User).filter(User.id==user_id).one()
        if user.balance <= 0:
            return None
        chat = sqlsession.query(Chat).filter(Chat.id==chat_id).one()
        if send_time != "":
            chat.history.append(History(content=send_time, role="system"))
        chat.history.append(History(content=message, role="user"))

        message_history = []
        have_chat_context = 0
        for h in chat.history:
            message_history.append({'role': h.role, 'content': h.content})
            if h.role in {'user', 'assistant'}:
                have_chat_context += 1
        sqlsession.commit()

    message_context = get_message_context(message_history, have_chat_context, chat_with_history)
    generate = get_response_stream_generate_from_ChatGPT_API(message_context, API_KEY, user_id, chat_id)
    return generate

def check_session(current_session):
    """
    检查session，如果不存在则创建新的session
    :param current_session: 当前session
    :return: 当前session
    """
    if current_session.get('session_id') is not None:
        print("existing session, session_id:\t", current_session.get('session_id'))
    else:
        current_session['session_id'] = uuid.uuid1()
        print("new session, session_id:\t", current_session.get('session_id'))
    return current_session['session_id']

def check_user_bind(current_session):
    """
    检查用户是否绑定，如果没有绑定则重定向到index
    :param current_session: 当前session
    :return: 当前session
    """
    if current_session.get('user_id') is None:
        return False
    return True

# 进入主页
@app.route('/', methods=['GET', 'POST'])
def index():
    """
    主页
    :return: 主页
    """
    check_session(session)
    return render_template('index.html')

# 进入登陆页
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    登陆页
    :return: 登陆页
    """
    return render_template('login.html')

# 进入充值页
@app.route('/redeem', methods=['GET', 'POST'])
def redeem():
    """
    充值页
    :return: 充值页
    """
    return render_template('redeem.html')

@app.route('/loadHistory', methods=['GET', 'POST'])
def load_messages():
    """
    加载聊天记录
    :return: 聊天记录
    """
    check_session(session)
    url = request.host_url + 'login'
    if session.get('user_id') is None:
        messages_history = [{"role": "assistant", "content": project_info},
                            {"role": "assistant", "content": f"请[登录]({url})"}]
    else:        
        with Session(engine) as sqlsession:
            history = sqlsession.query(History).filter(History.chat_id==session['chat_id']).all()
            messages_history = []
            for h in history:
                h_dict = {'content':h.content, 'role':h.role}
                messages_history.append(h_dict)

    return {"code": 0, "data": messages_history, "message": ""}

@app.route('/loadChats', methods=['GET', 'POST'])
def load_chats():
    """
    加载聊天联系人
    :return: 聊天联系人
    """
    check_session(session)
    if not check_user_bind(session):
        chats = []

    else:
        chats = []
        with Session(engine) as sqlsession:
            chatList = sqlsession.query(Chat).filter(Chat.user_id==session['user_id']).all()
            for chat in chatList:
                chats.append(
                    {"id": chat.id, "name": chat.name, "selected": chat.id==session['chat_id'], "messages_total": len(chat.history)}
                )

    return {"code": 0, "data": chats, "message": ""}

def get_balance(apikey):
    head = ""
    if apikey is not None:
        head = "###  用户专属api key余额  \n"
    else:
        head = "### 通用api key  \n"
        apikey = API_KEY

    headers = {
        "Authorization": "Bearer " + apikey,
        "Content-Type": "application/json"
    }
    subscription_response = requests.get(subscription_url, headers=headers)
    if subscription_response.status_code == 200:
        data = subscription_response.json()
        total = data.get("hard_limit_usd")
    else:
        return head+subscription_response.text

    # start_date设置为今天日期前99天
    start_date = (datetime.datetime.now() - datetime.timedelta(days=99)).strftime("%Y-%m-%d")
    # end_date设置为今天日期+1
    end_date = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    billing_url = f"{API_URL}/v1/dashboard/billing/usage?start_date={start_date}&end_date={end_date}"
    billing_response = requests.get(billing_url, headers=headers)
    if billing_response.status_code == 200:
        data = billing_response.json()
        total_usage = data.get("total_usage") / 100
        daily_costs = data.get("daily_costs")
        days = min(5, len(daily_costs))
        recent = f"##### 最近{days}天使用情况  \n"
        for i in range(days):
            cur = daily_costs[-i-1]
            date = datetime.datetime.fromtimestamp(cur.get("timestamp")).strftime("%Y-%m-%d")
            line_items = cur.get("line_items")
            cost = 0
            for item in line_items:
                cost += item.get("cost")
            recent += f"\t{date}\t{cost / 100} \n"
    else:
        return head+billing_response.text

    return head+f"\n#### 总额:\t{total:.4f}  \n" \
                f"#### 已用:\t{total_usage:.4f}  \n" \
                f"#### 剩余:\t{total-total_usage:.4f}  \n" \
                f"\n"+recent

# 注册接口
@app.route('/signup', methods=['GET', 'POST'])
def sign_up():
    check_session(session)
    username = request.values.get("username").strip().lower()
    password = request.values.get("password").strip()
    code = request.values.get("code").strip().lower()

    # 非法输入检测
    if len(username) > 16 or len(password) > 32:
        return {"code": 400, "data": "data too long"}
    if not re.search(u'^[a-zA-Z0-9]+$', username):
        return {"code": 400, "data": "username unexpect"}
    if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
        return {"code": 400, "data": "password unexpect"}
    
    # 检测验证码
    if not code == session['imageCode'].lower():
        return {"code": 400, "data": "验证码错误"}

    with Session(engine) as sqlsession:
        query = sqlsession.query(User).filter(User.username==username)
        if sqlsession.query(query.exists()).scalar():
            return {"code": 400, "data": "user exist"}
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        user = User(
            username=username,
            password=sha256.hexdigest(),
            balance=USER_BALANCE,
            chat=[]
        )
        user.chat.append(Chat(name="默认会话", history=[]))
        sqlsession.add(user)
        sqlsession.commit()
    return {"code": 200, "data": "sign up successfully"}

# 登录接口
@app.route('/signin', methods=['GET', 'POST'])
def sign_in():
    check_session(session)
    username = request.values.get("username").strip().lower()
    password = request.values.get("password").strip()
    code = request.values.get("code").strip().lower()

    # 非法输入检测
    if len(username) > 16 or len(password) > 32:
        return {"code": 400, "data": "data too long"}
    if not re.search(u'^[a-zA-Z0-9]+$', username):
        return {"code": 400, "data": "username unexpect"}
    if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
        return {"code": 400, "data": "password unexpect"}
    
    # 检测验证码
    if not code == session['imageCode'].lower():
        return {"code": 400, "data": "验证码错误"}

    with Session(engine) as sqlsession:
        query = sqlsession.query(User).filter(User.username==username)
        if not sqlsession.query(query.exists()).scalar():
            return {"code": 400, "data": "user not exist"}
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        
        stmt = select(User).where(User.username==username)
        user = sqlsession.scalars(stmt).one()
        if user.password == sha256.hexdigest():
            session['user_id'] = user.id
            session['chat_id'] = user.chat[0].id
            session['chat_with_history'] = False
            return {"code": 200, "data": "sign in successfully"}
        else:
            return {"code": 400, "data": "error password"}
    
@app.route('/signOut', methods=['GET', 'POST'])
def sign_out():
    session['user_id'] = None
    session['chat_id'] = None
    return redirect('/')

@app.route('/imgCode', methods=['GET', 'POST'])
def imgCode():
    check_session(session)
    return imageCode().getImgCode()

@app.route('/isLogin', methods=['GET', 'POST'])
def is_login():
    check_session(session)
    if not check_user_bind(session):
        return {"code": 200, "data": False}
    else:
        return {"code": 200, "data": True}

@app.route('/recharge', methods=['GET', 'POST'])
def recharge():
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}

    key = request.values.get("key").strip()
    code = request.values.get("code").strip().lower()
    if not code == session['imageCode'].lower():
        return {"code": 400, "data": "验证码错误"}
    with Session(engine) as sqlsession:
        query = sqlsession.query(Key).filter(Key.value==key)
        if not sqlsession.query(query.exists()).scalar():
            return {"code": 400, "data": "key not exist"}
        key_obj = sqlsession.query(Key).filter(Key.value==key).one()
        user = sqlsession.query(User).filter(User.id==session['user_id']).one()
        if key_obj.balance <= 0:
            return {"code": 400, "data": "key already used"}
        user.balance += key_obj.balance
        key_obj.balance = 0
        sqlsession.commit()
    return {"code": 200, "data": "recharge successfully"}

@app.route('/getName', methods=['GET', 'POST'])
def get_name():
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    
    with Session(engine) as sqlsession:
        user = sqlsession.query(User).filter(User.id==session['user_id']).one()
        return {"code": 200, "data": user.username}
    
@app.route('/checkBalance', methods=['GET', 'POST'])
def checkBalance():
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    with Session(engine) as sqlsession:
        user = sqlsession.query(User).filter(User.id==session['user_id']).one()
        return {"code": 200, "data": user.balance}

@app.route('/returnMessage', methods=['GET', 'POST'])
def return_message():
    """
    获取用户发送的消息，调用get_chat_response()获取回复，返回回复，用于更新聊天框
    :return:
    """
    check_session(session)
    send_message = request.values.get("send_message").strip()
    send_time = request.values.get("send_time").strip()

    if session.get('user_id') is None:  # 如果当前session未绑定用户
        return "未登录"
    else:
        user_id = session.get('user_id')
        chat_id = session.get('chat_id')
        chat_with_history = session.get('chat_with_history')
        print(f"用户({user_id})发送消息:{send_message}")
        if not STREAM_FLAG:
            content = handle_messages_get_response(send_message, send_time, user_id, chat_id, chat_with_history)
            print(f"用户({session.get('user_id')})得到的回复消息:{content[:40]}...")
            return content
        else:
            generate = handle_messages_get_response_stream(send_message, send_time, user_id, chat_id, chat_with_history)
            print(generate)
            if generate is None:
                return "余额不足"
            return app.response_class(generate(), mimetype='application/json')

@app.route('/getMode', methods=['GET'])
def get_mode():
    """
    获取当前对话模式
    :return:
    """
    check_session(session)
    if not check_user_bind(session):
        return "normal"

    if session['chat_with_history']:
        return {"mode": "continuous"}
    else:
        return {"mode": "normal"}


@app.route('/changeMode/<status>', methods=['GET'])
def change_mode(status):
    """
    切换对话模式
    :return:
    """
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请登录"}

    if status == "normal":
        session['chat_with_history'] = False
        print("开启普通对话")
        message = {"role": "system", "content": "切换至普通对话"}
    else:
        session['chat_with_history'] = True
        print("开启连续对话")
        message = {"role": "system", "content": "切换至连续对话"}
    return {"code": 200, "data": message}


@app.route('/selectChat', methods=['GET'])
def select_chat():
    """
    选择聊天对象
    :return:
    """
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    user_id = session.get('user_id')
    chat_id = int(request.args.get("id"))
    with Session(engine) as sqlsession:
        chats = sqlsession.query(Chat).filter(Chat.user_id==user_id).all()
        for chat in chats:
            if chat_id == chat.id:
                if user_id == chat.user_id:
                    session['chat_id'] = chat_id
                    return {"code": 200, "msg": "选择聊天对象成功"}
                else:
                    return {"code": 400, "msg": "无权限"}
    
    return {"code": 400, "msg": "无效ID"}


@app.route('/newChat', methods=['GET'])
def new_chat():
    """
    新建聊天对象
    :return:
    """
    name = request.args.get("name")
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    user_id = session.get('user_id')
    print("新建聊天对象")
    with Session(engine) as sqlsession:
        user = sqlsession.query(User).filter(User.id==user_id).one()
        user.chat.append(Chat(name=name, history=[]))
        sqlsession.commit()
        user = sqlsession.query(User).filter(User.id==user_id).one()
        chat_id = user.chat[-1].id
    session['chat_id'] = chat_id
    return {"code": 200, "data": {"name": name, "id": chat_id, "selected": True, "messages_total": 0}}


@app.route('/deleteHistory', methods=['GET'])
def delete_history():
    """
    清空上下文
    :return:
    """
    check_session(session)
    if not check_user_bind(session):
        print("请先创建或输入已有用户id")
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    user_id = session['user_id']
    chat_id = session['chat_id']
    with Session(engine) as sqlsession:
        user = sqlsession.query(User).filter(User.id==user_id).one()
        if user.chat[0].id == chat_id:
            print("清空历史记录")
            sqlsession.query(History).filter(History.chat_id==chat_id).delete()
        else:
            print("删除聊天对话")
            sqlsession.query(History).filter(History.chat_id==chat_id).delete()
            sqlsession.query(Chat).filter(Chat.id==chat_id).delete()
            session['chat_id'] = user.chat[0].id
        sqlsession.commit()
            
    return {"code": 200, "msg": "删除成功"}

if __name__ == '__main__':
    if len(API_KEY) == 0:
        # 退出程序
        print("请在openai官网注册账号，获取api_key填写至程序内或命令行参数中")
        exit()
    app.run(host="0.0.0.0", port=PORT, debug=False)
