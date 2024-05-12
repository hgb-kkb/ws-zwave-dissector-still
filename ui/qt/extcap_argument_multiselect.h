/* extcap_argument_multiselect.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_
#define UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_

#include <QObject>
#include <QWidget>
#include <QStandardItem>
#include <QTreeView>
#include <QAbstractItemModel>
#include <QItemSelection>

#include <extcap_parser.h>
#include <extcap_argument.h>

class ExtArgMultiSelect : public ExtcapArgument
{
    Q_OBJECT
public:
    ExtArgMultiSelect(extcap_arg * argument, QObject *parent = Q_NULLPTR);
    virtual ~ExtArgMultiSelect();

    virtual QString value();
    virtual bool isValid();

protected:
    virtual QList<QStandardItem *> valueWalker(ExtcapValueList list, QStringList &defaults);
    void checkItemsWalker(QStandardItem * item, QStringList defaults);
    virtual QWidget * createEditor(QWidget * parent);

private Q_SLOTS:

    void itemChanged(QStandardItem *);

private:

    QTreeView * treeView;
    QAbstractItemModel * viewModel;

};

#endif /* UI_QT_EXTCAP_ARGUMENT_MULTISELECT_H_ */
