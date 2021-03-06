//
// Created by Stefan Schwarz on 18/09/16.
//

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

using namespace std;

class Counter
{
public:
    Counter() { ++count_; }

    ~Counter() { --count_; }

    static int count() { return count_; }

private:
    static int count_;
};

int Counter::count_ = 0;

template<typename T>
struct reversion_wrapper
{
    T& iterable;
};

template<typename T>
auto begin(reversion_wrapper<T> w) { return rbegin(w.iterable); }

template<typename T>
auto end(reversion_wrapper<T> w) { return rend(w.iterable); }

template<typename T>
reverse_iterator<T> reverse(T&& iterable) { return {iterable}; }

class MyGraph
{
public:
    class Node : public Counter
    {
        vector<shared_ptr<Node>> children;

    public:
        void AddChild(const shared_ptr<Node>& node)
        {
            children.push_back(node);

        }

        void RemoveChild(const shared_ptr<Node>& node)
        {
            for (auto elem : (*node).children) {
                if (elem.get()->children.size()>=1) {
                    while (!(*elem).children.empty() && elem!=node) {
                        elem.get()->children.pop_back();
                    }
                }
                (*node).children.pop_back();
            }
//            while(!(*node).children.empty())
//            {
//                (*node).children.pop_back();
//            }
            children.erase(std::remove(children.begin(), children.end(), node),
                    children.end());
//            children.pop_back();
        }

    };

    void SetRoot(const shared_ptr<Node>& node)
    {
        root = node;

    }

    void ShrinkToFit()
    {

    }

    static auto MakeNode() { return make_shared<MyGraph::Node>(); }

private:
    shared_ptr<Node> root;

};

bool TestCase1()
{
    MyGraph g;
    {
        auto a = MyGraph::MakeNode();
        g.SetRoot(a);
        auto b = MyGraph::MakeNode();
        a->AddChild(b);
        auto c = MyGraph::MakeNode();
        b->AddChild(c);
        a->RemoveChild(b);
    }
    g.ShrinkToFit();
    return Counter::count()==1;
}

bool TestCase2()
{
    MyGraph g;
    {
        auto a = MyGraph::MakeNode();
        g.SetRoot(a);
        auto b = MyGraph::MakeNode();
        a->AddChild(b);
        auto c = MyGraph::MakeNode();
        b->AddChild(c);
        auto d = MyGraph::MakeNode();
        b->AddChild(d);
        d->AddChild(b);
        a->RemoveChild(b);
    }
    g.ShrinkToFit();
    return Counter::count()==1;
}

bool TestCase3()
{
    MyGraph g;
    {
        auto a = MyGraph::MakeNode();
        g.SetRoot(a);
        auto b = MyGraph::MakeNode();
        a->AddChild(b);
        auto c = MyGraph::MakeNode();
        b->AddChild(c);
        auto d = MyGraph::MakeNode();
        b->AddChild(d);
        d->AddChild(b);
    }
    g.ShrinkToFit();
    return Counter::count()==4;
}

bool TestCase4()
{
    MyGraph g;
    {
        auto a = MyGraph::MakeNode();
        g.SetRoot(a);
        auto b = MyGraph::MakeNode();
        a->AddChild(b);
        auto c = MyGraph::MakeNode();
        b->AddChild(c);
        auto d = MyGraph::MakeNode();
        b->AddChild(d);
        d->AddChild(b);
        d->RemoveChild(b);
    }
    g.ShrinkToFit();
    return Counter::count()==4;
}

int main()
{
    cout.setf(ios::boolalpha);

    cout << TestCase1() << endl;
    cout << TestCase2() << endl;
    cout << TestCase3() << endl;
    cout << TestCase4() << endl;
}
