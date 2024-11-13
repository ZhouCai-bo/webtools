class LANG:
    CHS = 'chs'
    CHT = 'cht'
    EN  = 'en'
    RU  = 'ru'
    VI = 'vi'
    FR = 'fr'
    PT = 'pt'
    ES = 'es'
    IT = 'it'

class API_ERROR:
    CHS = LANG.CHS
    CHT = LANG.CHT
    EN = LANG.EN
    RU = LANG.RU
    ES = LANG.ES
    PT = LANG.PT
    FR = LANG.FR
    VI = LANG.VI
    IT = LANG.IT

    SUCCESS = OK = (200, 0, {CHS: u'成功', CHT: u'成功', EN: u'Success', RU: u'ok', VI: u'Thành công', ES: u'ok', PT: u'ok', FR: u'ok', IT: u'Successo'})
    # 有时候不需要关注具体什么错误的时候，可以用这个
    FAILED = (400, 10001, {CHS: u'失败', CHT: u'失敗', EN: u'failed', RU: u'Ошибка', VI: u'Thất bại', ES: u'Error en el parámetro', PT: u'Erro de parâmetro', FR: u'Erreur de paramètre', IT: u'fallito'})
    BAD_PARAMS = (400, 10002, {CHS: u'参数错误', CHT: u'參數錯誤', EN: u'bad params', RU: u'Ошибка параметра', VI: u'tham số lỗi', IT: u'parametri sbagliati'})
    BAD_HEADER = (400, 10003, {CHS: u'请求头错误', CHT: u'請求頭錯誤', EN: u'bad header', RU: u'Ошибка заголовка запроса', VI: u'tiêu đề lỗi', IT: u'intestazione errata'})