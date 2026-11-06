# Changelog

## Unreleased

- Add the G2 signed generation/replica candidate with atomic completeness, restart-safe reception, persistent pins and separate revision-bound maintenance authority.
- Verify small-file restore after source repack/loss, direct checkpoint catch-up and five real replica SIGKILL boundaries; defer heavy acceptance and retain all production holds.

- Add the G1 independent file-kit candidate, local CLI, encrypted multipart descriptors, chunk reuse and standalone restoration.
- Add real SIGKILL, concurrent reader/maintenance and tamper rejection checks plus measured 128 MiB/100 GiB acceptance runners.
- Record specification 1.4's engine/format decision, resource bounds and bilingual requirement-to-check trace; retain G2/G3 and production holds.

- Start a separate Outpost repository for autonomous backup design.
- Publish specification 1.1 with trusted nodes, untrusted nodes and external storage.
- Define 53 requirements, 35 acceptance scenarios and mandatory G1-G3 gates.
- Connect Development Standard 0.4.0 with bilingual documentation and repository checks.
- Preserve the previous receiver in [outpost-legacy](https://github.com/nd4y/outpost-legacy).

The repository contains development file-kit code and a native restic comparison. It includes no production migration, deployed worker image or runtime release.

# Изменения

## Не выпущено

- Добавлен кандидат поколений и реплик G2: атомарная полнота, продолжение приёма после перезапуска, постоянные закрепления и отдельные полномочия обслуживания с привязкой к ревизии.
- Проверены восстановление малого файла после перепаковки и потери источника, переход к контрольной точке и пять реальных границ SIGKILL реплики; тяжёлая приёмка отложена, эксплуатационные ограничения сохранены.

- Добавлены кандидат независимого комплекта G1, локальный CLI, зашифрованные части описания, повторное использование блоков и самостоятельное восстановление.
- Добавлены реальные проверки SIGKILL, совместной работы читателя и обслуживания, повреждений и измеряемые сценарии 128 МиБ/100 ГиБ.
- В ТЗ 1.4 записаны выбор движка/формата, пределы ресурсов и двуязычная связь требований с проверками; G2/G3 и рабочая выкладка остаются отдельными этапами.

- Создан отдельный репозиторий Outpost для автономной системы резервного копирования.
- Опубликовано ТЗ 1.1 с доверенными нодами, недоверенными нодами и внешними хранилищами.
- Определены 53 требования, 35 сценариев приёмки и обязательные проверки G1-G3.
- Подключён стандарт разработки 0.4.0 с двуязычной документацией и проверками.
- Прежний приёмник сохранён в [outpost-legacy](https://github.com/nd4y/outpost-legacy).

Репозиторий содержит экспериментальный код файловых комплектов и сравнение с нативным restic. Производственная миграция, установленный образ воркера и runtime-релиз отсутствуют.
