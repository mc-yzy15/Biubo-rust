import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import zh from './zh.json'
import en from './en.json'

const resources = {
  zh: { translation: zh },
  en: { translation: en },
}

const savedLang = localStorage.getItem('biubo_lang') || 'zh'

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: savedLang === 'en' ? 'en' : 'zh',
    fallbackLng: 'zh',
    interpolation: {
      escapeValue: false,
    },
  })

export default i18n
